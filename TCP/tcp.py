#!/usr/bin/env python3.7
# Author: RJA Buddenbohmer
# See:    https://www.ietf.org/rfc/rfc2822.txt
#         https://tools.ietf.org/html/rfc1081
#         https://tools.ietf.org/html/rfc5321
#         https://tools.ietf.org/html/rfc2616

from scapy.all import *
from scapy.packet import *
from scapy.layers.inet import TCP
import json, re, base64, zipfile, tempfile, sys, os, subprocess, shutil

email_ports = [25, 110]          # SMTP and POP, as we saw in the Wireshark statistics
packets = rdpcap('./jim.pcapng') # The capture
mail_list = []                   # List of mails, constructed during analysis
attachment_list = []             # To be analysed in phase 3
password_candidates = set()      # Lijst van alle unieke woorden in het mailverkeer


def is_email_packet(packet):
    # All TCP packets with the correct port numbers and an actual payload
    return packet.haslayer(TCP) and (packet.dport in email_ports or packet.sport in email_ports) and packet[TCP].payload

def contains_message(packet):
    # We are only interested in packets with From and To fields in the payload
    content = bytes(packet[TCP].payload).decode("utf-8")
    return any(fieldname in content for fieldname in ["To: ", "From: "])

def is_message(packet):
    return is_email_packet(packet) and contains_message(packet)

def parse_payload(payload):
    # Extract the header bytes
    end_of_header = payload.find(b'\r\n\r\n')
    header_bytes = payload[:end_of_header]
    result = parse_header(header_bytes)
    # Extract and parse the data bytes
    data_bytes = payload[end_of_header:]
    data = parse_data(data_bytes, result)
    # Merge header and data
    result.update(data)
    return result

def parse_header(header):
    # Create a dictionary from all header fields
    header_dict = {}
    for line in header.split(b'\r\n'):
        # The +OK octets' line is not a header field
        if line and not line.startswith(b'+OK '):
           # Convert all multilines to singlelines 
           if not line.startswith(b' '):
              k, v = line.split(b":", 1) 
              header_dict[k.decode('utf-8')] = v.decode('utf-8').strip()
           else:
              last_key = list(header_dict.keys())[-1] 
              header_dict[last_key] += ' ' + line.strip().decode('utf')
    return header_dict

def parse_data(data, header):
    data_dict = {}
    # Do we have an attachment?
    if "multipart" in header['Content-Type']:
       boundary = get_boundary(header['Content-Type'])
       parts = [] 
       for section in data.split(boundary.encode()):
           if b'Content-Type' in section:
               parts.append(parse_payload(section))
       data_dict["parts"] = parts
    else:
       # TODO This only works for base64 encoded attachments and plain text now. Can be extended with other encoding types
       message_text = []
       for line in data.replace(b"\r\n.\r\n", b"").split(b'\r\n'):
           if line:
               text_string = line.decode('utf-8')
               message_text.append(text_string)
               #  Add the text to the password candidates  
               if "text" in header["Content-Type"]: add_to_candidates(text_string)
       data_dict["message_lines"] = message_text
    return data_dict

def add_to_candidates(text):
    password_candidates.update(text.split(" "))
    
def get_boundary(content_type):
    boundary = re.search(r'(?<=boundary=\")(.*)(?=\")', content_type).group(1)
    return "--" + boundary

def get_filename(content_disposition):
    return re.search(r'(?<=filename=)(.*)(?=;)', content_disposition).group(1)

def is_zip_encrypted(archive_name):
    zf = zipfile.ZipFile(archive_name)
    for zinfo in zf.infolist():
        is_encrypted = zinfo.flag_bits & 0x1 
    return is_encrypted

def default_crack(filename):
    for candidate in password_candidates:
        if candidate:
            try:
                with zipfile.ZipFile("./" + filename) as zip_ref:
                    zip_ref.extractall(tmpdirname, pwd=bytes(candidate, "utf-8"))
                    print("Extracted " + filename + " to temporary directory")
                    return True
            except Exception as e:
                if "Bad password" in str(e):
                    continue
                else:
                    break
    return False 

def _7z_crack(filename, tmp):
    for candidate in password_candidates:
        if candidate and filename and tmp:
            command = "7z x -p" + candidate.replace("'", "").replace("\"", "").replace(">", "") + " " + filename + " -y -o"+tmp
            try:
               completed_process = subprocess.run(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
               if not (completed_process.stderr and "Wrong password" in str(completed_process.stderr)):
                  return True    
            except subprocess.CalledProcessError:
               print("Something went wrong. Exitting...")
               sys.exit()
            except Exception:
               print("Something went wrong. Exitting...")
               sys.exit()
    return False

print("CRIMEDIGGERS  -  TCP/IP\n")
# First we need to collect all the required data
for pkt in packets:
    if is_message(pkt):
       mail = parse_payload(bytes(pkt[TCP].payload))
       mail_list.append(mail)
# Now we have all information structured, lets print a nice timeline
# TODO Put this in a function, it now disturbs reading the main programm flow
for mail in mail_list:
    print("{:<14} {}".format("Date:", mail["Date"]))
    print("{:<14} {}".format("Sender:", mail["From"]))
    print("{:<14} {}".format("Receiver:", mail["To"]))
    print("{:<14} {}".format("Subject:", mail["Subject"]))
    if "message_lines" in mail and "text" in mail["Content-Type"]:
       message_lines = mail["message_lines"] 
       print("{:<14} {}".format("Message:", message_lines[0]))
       for line in message_lines[1:]: print("{:<14} {}".format("", line))
    elif "parts" in mail:
        for part in mail["parts"]:
            if "Content-Type" in part and "text" in part["Content-Type"] and "message_lines" in part:
                message_lines = part["message_lines"] 
                print("{:<14} {}".format("Message:", message_lines[0]))
                for line in message_lines[1:]: print("{:<14} {}".format("", line)) 
            elif "attachment" in part["Content-Disposition"]:
                filename = get_filename(part["Content-Disposition"])
                print("{:<14} {}".format("Attachment:", filename))
                # Add attachment in list. Save to disk later
                # TODO This should be done during parsing, this section is only for printing
                attachment = ""
                # Last line is termination, don't need that. Therefore :-1
                for line in part["message_lines"][:-1]: attachment += line
                attachment_dict = {}
                attachment_dict["encoding"] = part["Content-Transfer-Encoding"]
                attachment_dict["filename"] = filename
                attachment_dict["file"] = attachment
                attachment_list.append(attachment_dict)
    print("".join(["-" for x in range(0, 100)]), end='\n\n\n', flush=True)       

#Save attachments
for attachment in attachment_list:
    filename = attachment["filename"]
    print("Saving {}".format(filename).ljust(50, "."), end="")
    try:
        # TODO implement more encodings
        file_content=base64.b64decode(attachment["file"])
        with open("./" + filename,"wb+") as f:
             f.write(file_content) 
             print("DONE")
    except Exception:
        print("FAILED")
        sys.exit()   

    # In case of zipped files, extract them
    # TODO implement more extentions/compressing formats
    # TODO don't check extention, but check the bytes
    if filename.endswith(".zip"):
        # Create tmp folder
        print("Creating temporary directory".ljust(50, "."), end="")
        try:
            with tempfile.TemporaryDirectory() as tmpdirname:
                 print("DONE")
        except Exception:
            print("FAILED")
            sys.exit()

        # Extract files to tmp
        # Check if zip is encrypted
        if is_zip_encrypted("./" + filename):
            print("Zip is encrypted. Trying to decrypt it".ljust(50, "."), end="")
            if default_crack(filename):
                print("DONE")
            else:
                if _7z_crack(filename, tmpdirname):
                    print("DONE")
                else:
                    print("FAILED")
                    sys.exit()
        else:
            try:
                with zipfile.ZipFile("./" + filename) as zip_ref:
                    zip_ref.extractall(tmpdirname)
                    print("Extracted " + filename + " to temporary directory")
            except Exception as e:
                print("Unable to extract, trying 7z")
                FNULL = open(os.devnull, 'w')
                try:
                    subprocess.check_call(["7z", "x", filename, "-o"+tmpdirname], stdout=FNULL)
                    print("Extracted " + filename + " with 7z to " + tmpdirname)
                except subprocess.CalledProcessError:
                    print("7z didn't succeed as well, your file sucks. Exitting...")
                    sys.exit()
        # Now check the contents of the tmp dir with the extracted files
        print("Checking content of archive".ljust(50, "."), end="")
        content = []
        for subdir, dirs, files in os.walk(tmpdirname):
            for file in files:
                filepath = subdir + os.sep + file
                # TODO Add more file support, check for MIME Type etc
                try:
                    with open(filepath, "r") as f:
                         for l in f:
                             content.append(l)        
                except UnicodeDecodeError:
                    pass # non-text data TODO implement this
                finally:
                    os.remove(filepath)
        print("DONE")            
        print("Content of " + file + ":\n")
        for line in content:
            print("{:<14} {}".format('', line))            
        os.rmdir(tmpdirname)
    else:
        # TODO check the content of the non-zip files
        pass
                        



