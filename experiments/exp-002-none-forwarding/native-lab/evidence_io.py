"""Evidence failures stop normal work but must not skip owned process cleanup."""
class EvidenceIO:
 def __init__(self,root,errors):self.root=root;self.errors=errors;self.failed=set()
 def write(self,name,body,mode):
  if name in self.failed:return False
  try:
   with (self.root/name).open(mode) as f:
    if f.write(body)!=len(body):raise OSError('Short evidence write')
   return True
  except Exception as error:
   self.failed.add(name);self.errors.append('evidence '+name+': '+type(error).__name__+': '+str(error));return False

def cleanup_drain(drain,poll,errors,seen):
 try:drain(100)
 except Exception as error:
  key=(type(error).__name__,str(error))
  if key not in seen:
   seen.add(key);errors.append('cleanup drain: '+key[0]+': '+key[1])
  # A broken evidence stream must not replace exact-child settlement polling.
  poll.poll(100)
