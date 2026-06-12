CURRENT TASK:
- compile 2 files: main, guard, socket manager
- share seed between them
- periodically check if there is a anonymous socket to connect to with random name based on this seed
- if there is no socket main creates manager that reopens it
- if guard sees the socket it tries to send data to it to check if main is running, if not it waits random time to restart it, after timeout it tries to connect one more time
- if main sees socket it checks for messages during each wakeup, if there is message it responds 

BIG PLAN:
- run loop in that payload that updates heartbeat file
- it should update it by creating new process with parent = 1
- no direct update - use mmap, close trick
- it should check for some killswitch place if it exists and if there is a file (for now)
- if there is one it should finish the payload
- there also should be guard processes that check if there is this running main process and should restart it if there is not
- place of pulse file should be random and based on a seed incrusted inside main and guards
- to not have multiple running main processes the
- there should be way to update payload, by placing new binary in new location and payload would be loaded next day or something like this and returned back if it was not updated multiple times in a row to prevent disabling by update.
- it needs to prevent comiled payload from using metadata to find and kill existing process, so I could not run same processes multiple times to kill existing. It could check data and hash in main process and guards.
- inject payload on one of systemd services start or when user session starts or by creating own service or bunch of services that start it
- inject into one of the list of known processes
