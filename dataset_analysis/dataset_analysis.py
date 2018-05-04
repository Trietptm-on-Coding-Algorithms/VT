import multiprocessing
import sys
import os
import re
import pandas as pd
import json
import subprocess

try:
	import yara
except ImportError:
	print("This module requires yara to work.")
	sys.exit()


AVCLASS_path="/home/luca/Scrivania/tesi/avclass-master/avclass_labeler.py"
err=open(os.devnull,"w")



def compile_ruleset(ruleset_path):
	if(os.path.isdir(ruleset_path)==False):
		print("Invalid directory given:", ruleset_path)
		sys.exit()

	rules_dictionary={}

	""" Creating the dictionary to import all rules at once. """
	for dir, subdirs, rule_files in os.walk(ruleset_path):
		for rule_file in rule_files:
			try:
				rule_file_w_path=os.path.join(dir, rule_file)
				yara.compile(rule_file_w_path)
				rules_namespace=rule_file
				rules_dictionary[rules_namespace]=rule_file_w_path
			except Exception as e:
				print("Syntax error opening file: "+rule_file_w_path+" -skipping.")


	print(rules_dictionary)
	compiled_rules=yara.compile(filepaths=rules_dictionary)
	return compiled_rules

class Consumer(multiprocessing.Process):

	def __init__(self, task_queue, result_queue, yara_ruleset):
		multiprocessing.Process.__init__(self)
		self.task_queue = task_queue
		self.result_queue = result_queue
		self.yara_ruleset = yara_ruleset

	def run(self):
		df = pd.DataFrame(columns=['Exe name', 'Family','first_seen', 'last_seen', 'total', 'positives', 'ssdeep', 'yara_detected', 'yara_matching_rules' ])
		#df = df.set_index('Exe name')
		while True:
			next_task = self.task_queue.get()
			if next_task is None:
				self.task_queue.task_done()
				self.result_queue.put(df)
				break
			dict=next_task(self.yara_ruleset)
			df=df.append(dict, ignore_index=True)
			self.task_queue.task_done()
		print("Process ended successfully.")
		return

class Task(object):
	def __init__(self, dir_path, json_name):
		self.dir_path = dir_path
		self.json_name = json_name

	def __call__(self, yara_ruleset):
		report_path=os.path.join(self.dir_path,self.json_name)
		json_file=open(report_path)
		print("Loading file ", report_path)
		data=json.load(json_file)
		cmd=[AVCLASS_path, "-vt" , report_path]
		mw_family=subprocess.check_output(cmd,stderr=err)
		family_name=mw_family.split(b"\t")[1].decode('ascii')[:-1]
		#print(data['Family'])



		""" Getting the executable related to the report ( NOTE: it is assumed NOT to be necessarily a .exe, but, if it is certain
			it could be better to create the name entirely)"""
		file_name_no_extension=self.json_name[:len(self.json_name)-5]
		exe_name=file_name_no_extension
		exe_path=os.path.join(self.dir_path,exe_name)


		matches = yara_ruleset.match(exe_path)
		dict = {}
		dict['Exe name'] = exe_name
		dict['Family'] = family_name
		dict['first_seen'] = data['first_seen']
		dict['last_seen'] = data['last_seen']
		dict['total'] = data['total']
		dict['positives'] = data['positives']
		dict['ssdeep'] = data['ssdeep']
		dict['yara_detected'] = (len(matches)>0)
		dict['yara_matching_rules'] = [_.rule for _ in matches]

		return dict

if __name__ == "__main__":
	samples_path=sys.argv[1]
	rules_path=sys.argv[2]
	proc_num=int(sys.argv[3])

	jobs=multiprocessing.JoinableQueue()
	results = multiprocessing.Queue()

	yara_ruleset=compile_ruleset(rules_path)

	consumers = [Consumer(jobs, results, yara_ruleset) for i in range(proc_num)]

	for c in consumers:
		c.start()

	json_file_list=list(filter(lambda x: re.match(".*\.json",x),os.listdir(samples_path)))

	for entry in json_file_list:
		jobs.put(Task(samples_path, entry))
	for c in range(proc_num):
		jobs.put(None)

	jobs.join()
	print("Main awake.")

	df_list = [results.get() for i in range(proc_num)]
	pd_dataset= pd.concat(df_list)

	yara_matches_count = len(pd_dataset[pd_dataset['yara_detected']==True])
	print("Yara rules detected "+str(yara_matches_count)+" samples")
	"""
	packer_detection_count= len(pd_dataset[pd_dataset['possibly packed']==True])
	print("Yara rules detected "+str(yara_matches_count)+" packers whereas the dumb rule detected "+str(packer_detection_count))
	detection_hit = len(pd_dataset[(pd_dataset['yara packing detection']==True) & (pd_dataset['possibly packed']==True)])
	detection_miss = len(pd_dataset[(pd_dataset['yara packing detection']==True) & (pd_dataset['possibly packed']==False)])
	detection_false = len(pd_dataset[(pd_dataset['yara packing detection']==False) & (pd_dataset['possibly packed']==True)])
	print("The dumb rule found "+str(detection_hit)+" also found by the yara rules")
	print("The dumb rule couldn't find "+str(detection_miss)+" of those found by the yara rules")
	print("The dumb rule found "+str(detection_false)+" false positives w.r.t. the yara rules")
	"""
	pd_dataset.to_csv(sys.argv[4])
