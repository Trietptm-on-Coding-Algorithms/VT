import sys

import ply.lex as lex
import ply.yacc as yacc
import re

# Appears that Ply needs to read the source, so disable bytecode.
sys.dont_write_bytecode


class ElementTypes:
  '''An enumeration of the element types emitted by the parser to the interpreter.'''

  RULE_NAME = 1
  METADATA_KEY_VALUE = 2
  STRINGS_KEY_VALUE = 3
  STRINGS_MODIFIER = 4
  IMPORT = 5
  CONDITION = 6
  SCOPE = 7
  TAG = 8
  INCLUDE = 9
  TERM = 10

class ParserInterpreter:
  '''Interpret the output of the parser and produce an alternative representation of Yara rules.'''

  rules = []

  currentRule = {}

  stringModifiersAccumulator = []
  importsAccumulator = []
  includesAccumulator = []
  termAccumulator = []
  condition = None
  scopeAccumulator = []
  tagAccumulator = []

  isPrintDebug = False

  def reset(self, isPrintDebug=False):
      self.rules = []

      self.currentRule = {}

      self.stringModifiersAccumulator = []
      self.importsAccumulator = []
      self.includesAccumulator = []
      self.termAccumulator = []
      self.scopeAccumulator = []
      self.tagAccumulator = []
      self.condition = None

      self.isPrintDebug = isPrintDebug


  def addElement(self, elementType, elementValue):
    '''Accepts elements from the parser and uses them to construct a representation of the Yara rule.'''

    if elementType == ElementTypes.RULE_NAME:
      self.currentRule["rule_name"] = elementValue

      self.readAndResetAccumulators()

      self.rules.append(self.currentRule)
      if self.isPrintDebug:
        print("--Adding Rule " + self.currentRule['rule_name'])
      self.currentRule = {}

    elif elementType == ElementTypes.METADATA_KEY_VALUE:
      if "metadata" not in self.currentRule:
        self.currentRule["metadata"] = {elementValue[0]: elementValue[1]}
      else:
        if elementValue[0] not in self.currentRule["metadata"]:
          self.currentRule["metadata"][elementValue[0]] = elementValue[1]
        else:
          if isinstance( self.currentRule["metadata"][elementValue[0]], list):
            self.currentRule["metadata"][elementValue[0]].append( elementValue[1] )
          else:
            self.currentRule["metadata"][elementValue[0]] = [ self.currentRule["metadata"][elementValue[0]], elementValue[1] ]

    elif elementType == ElementTypes.STRINGS_KEY_VALUE:
      string_dict = {'name': elementValue[0], 'value': elementValue[1]}

      if len(self.stringModifiersAccumulator)  > 0:
        string_dict["modifiers"] = self.stringModifiersAccumulator
        self.stringModifiersAccumulator = []

      if "strings" not in self.currentRule:
        self.currentRule["strings"] = [string_dict]
      else:
        self.currentRule["strings"].append(string_dict)

    elif elementType == ElementTypes.STRINGS_MODIFIER:
      self.stringModifiersAccumulator.append(elementValue)

    elif elementType == ElementTypes.IMPORT:
      self.importsAccumulator.append(elementValue)

    elif elementType == ElementTypes.INCLUDE:
      self.includesAccumulator.append(elementValue)
    elif elementType == ElementTypes.CONDITION:
      self.currentRule["condition"] = elementValue

    elif elementType == ElementTypes.SCOPE:
      self.scopeAccumulator.append(elementValue)

    elif elementType ==ElementTypes.TAG:
      self.tagAccumulator.append(elementValue)
    elif elementType == ElementTypes.TERM:
      self.termAccumulator.append(elementValue)

  def readAndResetAccumulators(self):
    '''Adds accumulated elements to the current rule and resets the accumulators.'''
    if len(self.importsAccumulator) > 0:
      self.currentRule["imports"] = self.importsAccumulator
      self.importsAccumulator = []

    if len(self.includesAccumulator) > 0:
      self.currentRule["includes"] = self.includesAccumulator
      self.includesAccumulator = []

    if len(self.termAccumulator) > 0:
      self.currentRule["condition_terms"] = self.termAccumulator
      self.termAccumulator = []

    if len(self.scopeAccumulator) > 0:
      self.currentRule["scopes"] = self.scopeAccumulator
      self.scopeAccumulator = []

    if len(self.tagAccumulator) > 0:
      self.currentRule["tags"] = self.tagAccumulator
      self.tagAccumulator = []

  def printDebugMessage(self, message):
    '''Prints a debug message emitted by the parser if self.isPrintDebug is True.'''
    if self.isPrintDebug:
      print(message)
    return True


# Create an instance of this interpreter for use by the parsing functions.
parserInterpreter = ParserInterpreter()

def parseString(inputString, isPrintDebug=False):
  '''This method takes a string input expected to consist of Yara rules,
  and returns a list of dictionaries that represent them.'''

  if isPrintDebug:
    parserInterpreter.isPrintDebug = True

  parserInterpreter.reset(isPrintDebug=isPrintDebug)

  # Run the PLY parser, which emits messages to parserInterpreter.
  parser.parse(inputString)

  return parserInterpreter.rules


########################################################################################################################
# LEXER
########################################################################################################################
tokens = [
  'BYTESTRING',
  'STRING',
  'REXSTRING',
  'EQUALS',
  'STRINGNAME',
  'STRINGNAME_ARRAY',
  'LPAREN',
  'RPAREN',
  'LBRACK',
  'RBRACK',
  'LBRACE',
  'RBRACE',
  'ID',
  'BACKSLASH',
  'FORWARDSLASH',
  'PIPE',
  'PLUS',
  'SECTIONMETA',
  'SECTIONSTRINGS',
  'SECTIONCONDITION',
  'COMMA',
  'STRINGCOUNT',
  'GREATERTHAN',
  'LESSTHAN',
  'GREATEREQUAL',
  'LESSEQUAL',
  'PERIOD',
  'COLON',
  'STAR',
  'MINUS',
  'AMPERSAND',
  'NEQ',
  'EQUIVALENT',
  'DOTDOT',
  'HEXNUM',
  'NUM',
  'SHIFT_LEFT',
  'SHIFT_RIGHT',
  'TILDE',
  'PERCENTAGE',
  'STRINGLENGTH',
  'DIMENSION'
]

reserved = {
  'all': 'ALL',
  'and': 'AND',
  'any': 'ANY',
  'ascii': 'ASCII',
  'at': 'AT',
  'contains': 'CONTAINS',
  'entrypoint': 'ENTRYPOINT',
  'false': 'FALSE',
  'filesize': 'FILESIZE',
  'for': 'FOR',
  'fullword': 'FULLWORD',
  'global': 'GLOBAL',
  'import': 'IMPORT',
  'in': 'IN',
  'include' : 'INCLUDE',
  'int8': 'INT8',
  'int16': 'INT16',
  'int32': 'INT32',
  'int8be': 'INT8BE',
  'int16be': 'INT16BE',
  'int32be': 'INT32BE',
  'matches': 'MATCHES',
  'nocase': 'NOCASE',
  'not': 'NOT',
  'of': 'OF',
  'or': 'OR',
  'private': 'PRIVATE',
  'rule': 'RULE',
  'them': 'THEM',
  'true': 'TRUE',
  'wide': 'WIDE',
  'uint8': 'UINT8',
  'uint16': 'UINT16',
  'uint32': 'UINT32',
  'uint8be': 'UINT8BE',
  'uint16be': 'UINT16BE',
  'uint32be': 'UINT32BE',
}

tokens = tokens + list(reserved.values())

# Regular expression rules for simple tokens
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_EQUIVALENT = r'=='
t_NEQ = r'!='
t_EQUALS = r'='
t_LBRACE = r'{'
t_RBRACE = r'}'
t_PLUS = r'\+'
t_PIPE = r'\|'
t_BACKSLASH = r'\\'
t_FORWARDSLASH = r'/'
t_COMMA = r','
t_GREATERTHAN = r'>'
t_LESSTHAN = r'<'
t_GREATEREQUAL = r'>='
t_LESSEQUAL = r'<='
t_PERIOD = r'\.'
t_COLON = r':'
t_STAR = r'\*'
t_LBRACK = r'\['
t_RBRACK = r'\]'
t_MINUS = r'\-'
t_AMPERSAND = r'&'
t_DOTDOT = r'\.\.'
t_SHIFT_LEFT = r'<<'
t_SHIFT_RIGHT = r'>>'
t_TILDE = r'~'
t_PERCENTAGE = r'%'

def t_COMMENT(t):
  r'(//.*)(?=\n)'
  pass
  # No return value. Token discarded

# http://comments.gmane.org/gmane.comp.python.ply/134
def t_MCOMMENT(t):
  #r'/\*(.|\n)*?\*/'
  r'/\*(.|\n|\r|\r\n)*?\*/'
  if '\r\n' in t.value:
    t.lineno += t.value.count('\r\n')
  else:
    t.lineno += t.value.count('\n')
  pass

# Define a rule so we can track line numbers
def t_NEWLINE(t):
  #r'\n+'
  r'(\n|\r|\r\n)+'
  t.lexer.lineno += len(t.value)
  t.value = t.value
  pass

def t_HEXNUM(t):
  r'0x[A-Fa-f0-9]+'
  t.value = t.value
  return t

def t_DIMENSION(t):
    r'(0x[A-Fa-f0-9]|[0-9])+(KB|kb|kB|Kb|MB|mb|mB|Mb)'
    t.value = t.value
    return t

def t_SECTIONMETA(t):
  r'meta:'
  t.value = t.value
  return t

def t_SECTIONSTRINGS(t):
  r'strings:'
  t.value = t.value
  return t

def t_SECTIONCONDITION(t):
  r'condition(\s)*:'
  t.value = t.value
  return t

def t_STRING(t):
  #r'".+?"(?<![^\\]\\")'
  #r'".*?"(?<![^\\]\\")(?<![^\\][\\]{3}")(?<![^\\][\\]{5}")'
  #r'"([^"]|\\")*"'
  r'"((?:[^\\"]|\\.)*)"|"([^\s"]+)"'
  t.value = t.value
  return t

def t_BYTESTRING(t):
  r'\{[\|\(\)\[\]\-\?a-fA-f0-9\s]+\}'
  t.value = t.value
  return t

def t_REXSTRING(t):
  r'\/.+\/[a-z]*'
  t.value = t.value
  return t

def t_STRINGNAME(t):
  r'\$[0-9a-zA-Z\-_\*]*'
  t.value = t.value
  return t

def t_STRINGNAME_ARRAY(t):
  r'@[0-9a-zA-Z\-_\*]*'
  t.value = t.value
  return t

def t_STRINGLENGTH(t):
    r'!([a-zA-Z]|[0-9]|_)+'
    t.value = t.value
    return t

def t_NUM(t):
  r'\d+(\.\d+)?|0x\d+'
  t.value = t.value
  return t

def t_ID(t):
  r'[a-zA-Z_]{1}[a-zA-Z_0-9]*'
  t.type = reserved.get(t.value, 'ID')  # Check for reserved words
  return t

def t_STRINGCOUNT(t):
  r'\#[a-zA-Z0-9_]*'
  t.value = t.value
  return t


# A string containing ignored characters (spaces and tabs)
#t_ignore = ' \t\r\n'
t_ignore = ' \t'

# Error handling rule
def t_error(t):
  raise TypeError("Illegal character " + t.value[0] + " at line " + str(t.lexer.lineno))
  t.lexer.skip(1)

precedence = (  ('right', 'NUM') , ('right', 'ID'), ('right', 'HEXNUM'),
                ('left','OR'), ('left','AND'), ('left','PIPE'), ('left','AMPERSAND'),
                 ('left', 'EQUIVALENT','NEQ'), ('left','LESSTHAN','LESSEQUAL','GREATERTHAN','GREATEREQUAL'),
                 ('left','SHIFT_LEFT','SHIFT_RIGHT'),('left', 'PLUS', 'MINUS'),
                 ('left','STAR','BACKSLASH','PERCENTAGE'), ('right','NOT','TILDE','UMINUS'))

lexer = lex.lex(debug=False)

########################################################################################################################
# PARSER
########################################################################################################################

def p_rules(p):
  '''rules : rules rule
           | rule'''


def p_rule(p):
  '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''

  parserInterpreter.printDebugMessage('matched rule ' + str(p[3]))
  parserInterpreter.addElement(ElementTypes.RULE_NAME, str(p[3]))

def p_imports_and_scopes(p):
  '''imports_and_scopes : imports
                        | includes
                        | scopes
                        | imports scopes
                        | includes scopes
                        | '''

def p_imports(p):
  '''imports : imports import
             | includes
             | import'''

def p_includes(p):
  '''includes : includes include
              | imports
              | include'''

def p_import(p):
  'import : IMPORT STRING'
  parserInterpreter.printDebugMessage('...matched import ' + p[2])
  parserInterpreter.addElement(ElementTypes.IMPORT, p[2])

def p_include(p):
  'include : INCLUDE STRING'
  parserInterpreter.printDebugMessage('...matched include ' + p[2])
  parserInterpreter.addElement(ElementTypes.INCLUDE, p[2])

def p_scopes(p):
  '''scopes : scopes scope
            | scope'''

def p_tag_section(p):
  '''tag_section : COLON tags
                 | '''

def p_tags(p):
  '''tags : tags tag
          | tag'''

def p_tag(p):
  'tag : ID'
  parserInterpreter.printDebugMessage('matched tag ' + str(p[1]))
  parserInterpreter.addElement(ElementTypes.TAG, p[1])

def p_scope(p):
  '''scope : PRIVATE
           | GLOBAL'''
  parserInterpreter.printDebugMessage('matched scope identifier ' + str(p[1]))
  parserInterpreter.addElement(ElementTypes.SCOPE, p[1])

def p_rule_body(p):
  'rule_body : sections'
  parserInterpreter.printDebugMessage('...matched rule body')

def p_rule_sections(p):
  '''sections : sections section
            | section'''

def p_rule_section(p):
  '''section : meta_section
             | strings_section
             | condition_section'''

def p_meta_section(p):
  'meta_section : SECTIONMETA meta_kvs'
  parserInterpreter.printDebugMessage('...matched meta section')

def p_strings_section(p):
  'strings_section : SECTIONSTRINGS strings_kvs'

def p_condition_section(p):
  'condition_section : SECTIONCONDITION bool_expression'
  parserInterpreter.addElement(ElementTypes.CONDITION, p[2])

# Meta elements.

def p_meta_kvs(p):
  '''meta_kvs : meta_kvs meta_kv
              | meta_kv'''
  parserInterpreter.printDebugMessage('...matched meta kvs')

def p_meta_kv(p):
  '''meta_kv : ID EQUALS STRING
             | ID EQUALS ID
             | ID EQUALS TRUE
             | ID EQUALS FALSE
             | ID EQUALS NUM'''
  key = str(p[1])
  value = str(p[3])
  parserInterpreter.printDebugMessage('matched meta kv: ' + key + " equals " + value)
  parserInterpreter.addElement(ElementTypes.METADATA_KEY_VALUE, (key, value))

# Strings elements.

def p_strings_kvs(p):
  '''strings_kvs : strings_kvs strings_kv
                 | strings_kv'''
  parserInterpreter.printDebugMessage('...matched strings kvs')

def p_strings_kv(p):
  '''strings_kv : STRINGNAME EQUALS STRING
                | STRINGNAME EQUALS STRING string_modifiers
                | STRINGNAME EQUALS BYTESTRING
                | STRINGNAME EQUALS REXSTRING
                | STRINGNAME EQUALS REXSTRING string_modifiers'''

  key = str(p[1])
  value = str(p[3])
  parserInterpreter.printDebugMessage('matched strings kv: ' + key + " equals " + value)
  parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, (key, value))

def p_string_modifers(p):
  '''string_modifiers : string_modifiers string_modifier
                      | string_modifier'''

def p_string_modifier(p):
  '''string_modifier : NOCASE
                     | ASCII
                     | WIDE
                     | FULLWORD'''
  parserInterpreter.printDebugMessage('...matched a string modifier: ' + p[1])
  parserInterpreter.addElement(ElementTypes.STRINGS_MODIFIER, p[1])


# Condition elements.

def p_bool_expression(p):
    ''' bool_expression : expression'''
    p[0] = p[1]

def p_integer_set(p):
    ''' integer_set :   LPAREN integer_enumeration RPAREN
                    |   RANGE
                    '''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]

def p_expression(p):
    '''expression : TRUE
                | FALSE
                | primary_expression MATCHES REXSTRING
                | primary_expression CONTAINS primary_expression
                | STRINGNAME
                | STRINGNAME AT primary_expression
                | STRINGNAME IN LPAREN primary_expression_range RPAREN
                | FOR for_expression ID IN integer_set COLON LPAREN bool_expression RPAREN
                | FOR for_expression OF string_set COLON LPAREN bool_expression RPAREN
                | for_expression OF string_set
                | NUM OF string_set
                | NOT bool_expression
                | bool_expression AND bool_expression
                | bool_expression OR bool_expression
                | primary_expression LESSTHAN primary_expression
                | primary_expression GREATERTHAN primary_expression
                | primary_expression LESSEQUAL primary_expression
                | primary_expression GREATEREQUAL primary_expression
                | primary_expression EQUIVALENT primary_expression
                | primary_expression NEQ primary_expression
                | primary_expression
                | LPAREN expression RPAREN
    '''
    if len(p)==4 and p[2] == "of":
        p[0] = ""
        if p[1] == "any" or p[1] == "all":
            conn = ""
            if p[1] == "any":
                conn = "or "
                p[0] +="("
            elif p[1] == "all":
                conn = "and"
            if len(p[3])>1:
                string_enum = p[3][1:-1]
            else:
                string_enum = p[3]
            for entry in string_enum:
                if entry == "them" and len(parserInterpreter.currentRule["strings"][0]["name"])>1:
                    for string_dict in parserInterpreter.currentRule["strings"]:
                        string_name = string_dict["name"]
                        p[0]+=string_name+" "+conn+" "
                        parserInterpreter.addElement(ElementTypes.TERM,string_name)
                elif entry == "them" and len(parserInterpreter.currentRule["strings"][0]["name"])==1:
                    p[0]+=p[1]+" "+p[2]+" "+entry+"     "
                    if p[1] == "any":
                        start = 1
                    else:
                        start = 0
                    parserInterpreter.addElement(ElementTypes.TERM,p[0][start:-5])
                elif re.match("^\$.*\*",entry):
                    entry = entry.replace("$","\\$").replace("*",".*")
                    for string_dict in parserInterpreter.currentRule["strings"]:
                        string_name = string_dict["name"]
                        if re.match(entry,string_name):
                            p[0]+=string_name+" "+conn+" "
                            parserInterpreter.addElement(ElementTypes.TERM,string_name)
                else:
                    p[0]+=entry+" "+conn+" "
                    parserInterpreter.addElement(ElementTypes.TERM, entry)

            p[0]=p[0][:-4]
            if conn == "or ":
                p[0]=p[0][:-1]+")"
        else:
            if(p[3][0]!="them"):
                p[0] = p[1]+" "+p[2]+" "+"("+",".join(p[3][1:-1])+")"
            else:
                p[0] = p[1]+" "+p[2]+" "+p[3][0]
            parserInterpreter.addElement(ElementTypes.TERM,p[0])
    else:
        p[0] = ""
        for i in range(1,len(p)):
            if isinstance(p[i],list):
                p[0]+="".join(p[i])
            else:
                p[0]+=p[i]+" "
        if (len(p)!=4 or( p[2] != "and" and p[2] != "or")) and p[1]!="not" and p[1] != "(":
            parserInterpreter.addElement(ElementTypes.TERM,p[0][:-1])
        p[0]=p[0][:-1]

def p_range(p):
    ''' RANGE : LPAREN primary_expression DOTDOT primary_expression RPAREN'''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]

def p_integer_enumeration(p):
    ''' integer_enumeration : primary_expression
                            | integer_enumeration COMMA primary_expression
                            '''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]

def p_integer_function(p):
    '''  integer_function : UINT8
                          | UINT16
                          | UINT32
                          | UINT8BE
                          | UINT16BE
                          | UINT32BE
                          | INT8
                          | INT16
                          | INT32
                          | INT8BE
                          | INT16BE
                          | INT32BE'''
    p[0] = p[1]
def p_string_set(p):
    ''' string_set : LPAREN string_enumeration RPAREN
                   | THEM
                   '''
    p[0] = [p[1]]
    if len(p) > 2:
        p[0].extend(p[2])
        p[0].append(p[3])


def p_string_enumeration(p):
    ''' string_enumeration : string_enumeration_item
                           | string_enumeration COMMA string_enumeration_item
                           '''
    if len(p) > 2:
        p[1].append(p[3])
        p[0] = p[1]
    else:
        p[0] = [p[1]]


def p_string_enumeration_item(p):
    ''' string_enumeration_item : STRINGNAME '''
    p[0] = p[1]


def p_for_expression(p):
    ''' for_expression  : primary_expression
                        | ALL
                        | ANY
                        '''
    p[0] = p[1]


def p_var(p):
    ''' var :   ID
            |   var LPAREN RPAREN
            |   var LBRACK primary_expression RBRACK
            |   var PERIOD ID
            '''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]


def p_primary_expression_set(p):
    ''' primary_expression_set  :   primary_expression
                                |   primary_expression_set COMMA primary_expression
    '''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]

def p_primary_expression_range(p):
    ''' primary_expression_range    :   primary_expression DOTDOT primary_expression
    '''
    p[0] = ""
    for i in range(1,len(p)):
        p[0]+=p[i]


def p_primary_expression(p):
    ''' primary_expression  :   LPAREN primary_expression RPAREN
                            |   FILESIZE
                            |   ENTRYPOINT
                            |   integer_function LPAREN primary_expression RPAREN
                            |   HEXNUM
                            |   NUM
                            |   DIMENSION
                            |   STRING
                            |   var LPAREN primary_expression_set RPAREN
                            |   var LPAREN primary_expression_range RPAREN
                            |   var LPAREN string_enumeration RPAREN
                            |   var LPAREN integer_enumeration RPAREN
                            |   STRINGCOUNT
                            |   STRINGNAME_ARRAY LBRACK primary_expression RBRACK
                            |   STRINGNAME_ARRAY
                            |   STRINGLENGTH LBRACK primary_expression RBRACK
                            |   STRINGLENGTH
                            |   var
                            |   MINUS primary_expression %prec UMINUS
                            |   primary_expression PLUS primary_expression
                            |   primary_expression MINUS primary_expression
                            |   primary_expression STAR primary_expression
                            |   primary_expression BACKSLASH primary_expression
                            |   primary_expression AMPERSAND primary_expression
                            |   primary_expression PIPE primary_expression
                            |   TILDE primary_expression
                            |   primary_expression SHIFT_LEFT primary_expression
                            |   primary_expression SHIFT_RIGHT primary_expression
                            |   REXSTRING
                            '''
    p[0] = ""
    for i in range(1,len(p)):
        if isinstance(p[i], list):
            p[0]+="".join(p[i])
        else:
            p[0]+=p[i]


"""
def p_array(p):
    ''' array : ID LBRACK NUM RBRACK '''

def p_condition(p):
  '''term : ID
          | STRING
          | NUM
          | HEXNUM
          | LPAREN
          | RPAREN
          | array
          | DOTDOT
          | EQUIVALENT
          | EQUALS
          | NEQ
          | PLUS
          | PIPE
          | BACKSLASH
          | FORWARDSLASH
          | COMMA
          | GREATERTHAN
          | LESSTHAN
          | GREATEREQUAL
          | LESSEQUAL
          | PERIOD
          | COLON
          | STAR
          | MINUS
          | AMPERSAND
          | ALL
          | AND
          | ANY
          | AT
          | CONTAINS
          | ENTRYPOINT
          | FALSE
          | FILESIZE
          | FOR
          | IN
          | INT8
          | INT16
          | INT32
          | INT8BE
          | INT16BE
          | INT32BE
          | MATCHES
          | NOT
          | OR
          | OF
          | THEM
          | TRUE
          | UINT8
          | UINT16
          | UINT32
          | UINT8BE
          | UINT16BE
          | UINT32BE
          | STRINGNAME
          | STRINGNAME_ARRAY
          | STRINGCOUNT'''


  parserInterpreter.printDebugMessage('...matched a term: ' + p[1])
  parserInterpreter.addElement(ElementTypes.TERM, p[1])
  """
# Error rule for syntax errors
def p_error(p):
    raise TypeError("unknown text at %r ; token of type %r" % (p.value, p.type))


parser = yacc.yacc(debug=False)
