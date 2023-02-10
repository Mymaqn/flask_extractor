# flask_extractor
Tool for extracting FLASK session secret keys from a memory dump

## Dependencies
flask_extractor depends on flask_unsign
`pip3 install flask-unsign`

flask_dumper depends on nothing

## TODO
Currently is only able to extract secret keys if they are a byte string. Should support normal strings as well
User is required to supply a flask session cookie, to get started. It should be possible to extract these from the dump as well
