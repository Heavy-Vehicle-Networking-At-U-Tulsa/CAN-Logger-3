import paseto
import secrets
my_key = secrets.token_bytes(32)
# > b'M\xd48b\xe2\x9f\x1e\x01[T\xeaA1{Y\xd1y\xfdx\xb5\xb7\xbedi\xa3\x96!`\x88\xc2n\xaf'

# create a paseto token that expires in 5 minutes (300 seconds)
token = paseto.create(
        key=my_key,
        purpose='local',
        claims={'my claims': [1, 2, 3]},
        exp_seconds=300
)
# > b'v2.local.g7qPkRXfUVSxx3jDw6qbAVDvehtz_mwawYsCd5IQ7VmxuRFIHxY9djMaR8M7LWvCSvCZu8NUk-Ta8zFC5MpUXldBCKq8NtCG31wsoKv8zCKwDs9LuWy4NX3Te6rvlnjDMcI_Iw'

parsed = paseto.parse(
        key=my_key,
        purpose='local',
        token=token,
)
print(parsed['message'])