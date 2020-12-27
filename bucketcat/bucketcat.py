import os
import re
import sys
import boto3
import queue
import string
import argparse
import threading

from uuid import uuid4
from functools import reduce
from botocore.exceptions import ClientError

key_index = 0
mask_index = 0
lock = threading.Lock()
masks = []
keyspaces = {
  '?l' : string.ascii_lowercase,
  '?u' : string.ascii_uppercase,
  '?d' : string.digits,
  '?s' : string.punctuation,
  '?a' : string.printable
}

class Runner(threading.Thread):
  def __init__(self, bucket, aws_profile, obj_queue):
    threading.Thread.__init__(self)
    self.bucket = bucket
    self.obj_queue = obj_queue
    self.die = False

    session = boto3.session.Session(profile_name=aws_profile) if aws_profile else boto3.session.Session()
    self.s3 = session.resource('s3')

  def run(self):
    key = get_next_key()
  
    while not self.die and key:
      try:
        obj = self.s3.Object(self.bucket, key)
        obj.get(Range='0-1')
        self.obj_queue.put(key)
      except ClientError as e:
        pass

      key = get_next_key()

def get_next_key():
  global key_index, mask_index

  with lock:
    if get_search_space(masks[mask_index]) == key_index:
      if (mask_index+1) == len(masks):
        return None
      else:
        key_index = 0
        mask_index += 1

    key = build_key()
    key_index += 1

  return key

def build_key():
  mask = masks[mask_index]
  out = ''

  p = re.compile('\?.')
  keys = p.findall(mask)
  key_lens = [len(keyspaces[k]) for k in keys]
  key_chars = []

  for i, k in enumerate(keys):
    if i == (len(keys)-1):
      char_i = key_index % key_lens[i]
    else:
      key_len = reduce(lambda x, y: x*y, key_lens[i+1:])
      char_i = int(key_index / key_len) % key_len 
      
    key_chars.append(keyspaces[k][char_i])

  final_string = ''
  for c, k in zip(key_chars, keys):
    i = mask.index(k)
    final_string += mask[:i]
    final_string += c
    mask = mask[i+2:]

  final_string += mask
  return final_string

def get_search_space(mask):
  p = re.compile('\?.')
  keys = p.findall(mask)
  return reduce(lambda x, y: x*y, [len(keyspaces[k]) for k in keys])

def parse_hcmask_file(hcmask):
  p = re.compile('^\?\d\s')

  masks = []
  with open(hcmask, 'r') as f:
    for l in f:
      l = l.strip()
      if len(l) == 0:
        continue

      m = p.match(l)
      if m:
        keyspaces[m.group().strip()] = l[m.end():]
      else:
        masks.append(l)

  return masks

def verify_mask(mask):
  p = re.compile('\?.')
  mask_keyspaces = set(p.findall(mask))
  
  for ks in mask_keyspaces:
    try:
      keyspaces[ks]
    except KeyError:
      print('[!] Undefined keyspace in mask: {} -- exiting'.format(ks))

  return True

if __name__ == '__main__':
  parser = argparse.ArgumentParser()

  group = parser.add_mutually_exclusive_group()
  group.add_argument('-m', '--mask', help='Hashcat-like mask for S3 objects')
  group.add_argument('-f', '--infile', help='File with multiple Hashcat-like masks')

  parser.add_argument('-k', '--credsfile', help='File with the AWS credentials to use. Defaults to .env', default='.env')
  parser.add_argument('-p', '--profile', help='AWS profile to use.')
  parser.add_argument('-b', '--bucket', help='Target bucket')
  parser.add_argument('-t', '--threads', help='Number of threads to run with. Defaults to 1.', type=int, default=1)
  parser.add_argument('-o', '--outfile', help='Outfile to dump results to. Defaults to stdout.')
  parser.add_argument('-s', '--server', help='Run as a server in distributed mode (not yet supported)', action='store_true')
  parser.add_argument('-c', '--client', help='Run as a client in distributed mode (not yet supported)', action='store_true')

  args = parser.parse_args()

  if args.server or args.client:
    print('[!] Distributed mode not yet supported -- exiting')
    sys.exit(1)

  if not args.mask and not args.infile:
    print('[!] Must specify either an individual mask or an hcmask file -- exiting')
    sys.exit(1)

  if not os.path.isfile(args.credsfile):
    print('[!] Could not find the AWS credentials file specificied: {} -- exiting'.format(args.credsfile))
    sys.exit(1)

  if not args.bucket:
    print('[!] No bucket specified -- exiting')
    sys.exit(1)

  orig_cred_file = os.environ.get('AWS_SHARED_CREDENTIALS_FILE', None)
  os.environ['AWS_SHARED_CREDENTIALS_FILE'] = args.credsfile

  if args.infile:
    masks = parse_hcmask_file(args.infile)
  else:
    masks = [args.mask]

  for mask in masks:
    if not verify_mask(mask):
      sys.exit(1)

  search_space = sum([get_search_space(mask) for mask in masks])
  print('[*] Specified mask(s) will require {} requests to fully search. Continue? (y/n)'.format(search_space))
  con = input('')

  if con.lower() != 'y':
    sys.exit(1)

  obj_queue = queue.Queue()
  runners = []
  for i in range(args.threads):
    runners.append(Runner(bucket=args.bucket, aws_profile=args.profile, obj_queue=obj_queue))

  print('[*] Starting {} threads'.format(args.threads))

  try:
    valid_objects = []
    [r.start() for r in runners]

    mask_space = get_search_space(masks[0])
    current_mask = 0
    barLength = 10 #
    status = ''

    print('[*] Current mask: {}'.format(masks[0]))

    while True in [r.isAlive() for r in runners]:
      if mask_index > current_mask:
        text = '\r[{0}] {1:.2f}%'.format('#'*barLength, 100)
        sys.stdout.write(text)
        sys.stdout.flush()

        current_mask = mask_index
        mask_space = get_search_space(masks[current_mask])
        print('\n\n[*] Current mask: {}'.format(masks[current_mask]))

      progress = key_index / mask_space
      if progress >= 1:
        progress = 1

      block = int(round(barLength * progress))
      text = '\r[{0}] {1:.2f}%'.format('#'*block + '-'*(barLength-block), progress*100)
      sys.stdout.write(text)
      sys.stdout.flush()

    while not obj_queue.empty():
      valid_objects.append(obj_queue.get())

    print('\n\n[*] Finished -- {} objects discovered'.format(len(valid_objects)))

    if args.outfile:
      print('[*] Writing discovered objects to outfile: {}'.format(args.outfile))
      with open(args.outfile, 'w') as f:
        for obj in valid_objects:
          f.write('{}\n'.format(obj))
    else:
      print('')
      for obj in valid_objects:
        print(obj)
  except KeyboardInterrupt:
    print('[*] Exiting...')
    for r in runners:
      r.die = True
    [r.join() for r in runners]

  if orig_cred_file:
    os.environ['AWS_SHARED_CREDENTIALS_FILE'] = orig_cred_file
  else:
    del os.environ['AWS_SHARED_CREDENTIALS_FILE']
