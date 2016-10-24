import requests


key = "key-17a26be52da6de54e5987e665550111d"
sandbox = "/v3/sandbox626c2cd6928446d0bd05e52ea8550a78.mailgun.org/messages"
data={"from": "magdyshaban@yahoo.com",
  "to": ["magdyshaban@yahoo.com"],
  "subject": "Hello",
  "text": "Testing some Mailgun awesomness!"}

requests.post("https://api.mailgun.net/v3/sandbox626c2cd6928446d0bd05e52ea8550a78.mailgun.org/messages", auth=("api",key), data=data,verify=False)