import json

def parse_sysmon_log(log_file):
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                event_id = event.get('EventID')
                if event_id == 1: # Process Create
                    image = event['EventData']['Image']
                    command_line = event['EventData']['CommandLine']
                    print(f"Process Created: {image} | Cmd: {command_line}")
            except Exception as e:
                continue

if __name__ == "__main__":
    parse_sysmon_log("sysmon_logs.json")
