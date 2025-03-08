import re

class Validate:

  @staticmethod
  def zip(input):
    if re.match("^[0-9]{5}$", input):
      return True
    return False
  
  @staticmethod
  def minor(age):
    if age > 17:
      return False
    return True
  
  @staticmethod 
  def email(input):
    pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]+([.-][a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$", re.IGNORECASE)

    if re.match(pattern, input):
      print('match')
      return True
    print('does not match')
    return False
  
  @staticmethod
  def is_lat(number):
    if type(number) not in [int, float]:
      return False
    return number >= -90 and number <= 90
  
  @staticmethod
  def is_lng(number):
    if type(number) not in [int, float]:
      return False
    return number >= -180 and number <= 180
  
  @staticmethod
  def is_domain(input):
    pattern = re.compile(
      r'^(?!\-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    )
    
    # Match the input against the pattern
    if re.match(pattern, input):
        # Ensure domain length is between 1 and 253 characters
        if 1 <= len(input) <= 253:
            return True
    return False
  
  @staticmethod
  def is_url(input):
    pattern = re.compile(
        r'^(https?://)'
        r'([A-Za-z0-9-]+\.)*'
        r'[A-Za-z0-9-]+'
        r'(\.[A-Za-z]{2,})'
        r'(:\d+)?'
        r'(/[^?]*)?'
        r'(\?[A-Za-z0-9&=._-]*)?'
        r'(#\S*)?$'
        , re.IGNORECASE
    )
    
    if re.match(pattern, input):
        return True
    return False
  
  @staticmethod
  def grade(value):
    if type(value) != int and type(value) != float or value < 60:
      return 'F'
    if value < 70:
      return 'D'
    elif value < 80:
      return 'C'
    elif value < 90:
      return 'B'
    elif value > 90:
      return 'A'
  
  '''
  Typing added to enhance validation
  '''
  @staticmethod
  def sanitize(sql : str) -> str:
    sql = sql.upper().replace("ADMIN", "")
    sql = sql.upper().replace("OR", "")
    sql = sql.upper().replace("COLLATE", "")
    sql = sql.upper().replace("DROP", "")
    sql = sql.upper().replace("AND", "")
    sql = sql.upper().replace("UNION", "")
    sql = sql.replace("/*", "")
    sql = sql.replace("*/", "")
    sql = sql.replace("//", "")
    sql = sql.replace(";", "")
    sql = sql.replace("||", "")
    sql = sql.replace("&&", "")
    sql = sql.replace("--", "")
    sql = sql.replace("#", "")
    sql = sql.replace("=", "")
    sql = sql.replace("!=", "")
    sql = sql.replace("<>", "")

    return sql

  @staticmethod
  def strip_null(input : str) -> str:
    input = input.replace("None", "")

    return input

  '''
  TODO: Implement IP validation. Consider white-list, regex.
  '''
  @staticmethod
  def ip(input) -> bool:
    return True
  
  '''
  TODO: Implement MAC address validation. Consider white-list, regex.

  allow : - and whitespaces
  '''
  @staticmethod
  def mac(input) -> bool:
    return True
  
  '''
  TODO: Implement md5 validation. Consider white-list, regex.
  '''
  @staticmethod
  def md5(input) -> bool:
    return True