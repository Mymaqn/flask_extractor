# flask_extractor
Tool for extracting FLASK session secret keys from a memory dump

Currently supports trying to find it from bytestring or string objects. Let me know if there are other types which can be used.

If you use it on a distribution or version where it doesn't work, let me know.

## Dependencies
flask_extractor depends on flask_unsign
```
pip3 install flask-unsign
```

flask_dumper depends on nothing

## Usage

First dump a flask sessions memory using flask_dumper.py

```
python3 flask_dumper.py -p <PID> -o <optional output file prefx>
```

The dumper will always output the file with the prefix given and a .dmp and .maps extension.

Eg. output file prefix "abcd" will generate a file called "abcd.dmp" and "abcd.maps"

Then parse it using flask_extractor.py

```
python3 flask_extractor.py -f <.dmp file> -m <.maps file> -c <A valid session cookie>
```
## TODO

User is required to supply a flask session cookie, to get started. It should be possible to extract these from the dump as well
