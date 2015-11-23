# FPSPy3
Python 3 driver for Fingerprint Scanner GT-511C3

## Constructor
* Input
 * port: \<string\>
 * baud: \<integer\> data exchange speed
 * timeout: \<integer\> seconds for timeout

## init()
To connect a fingerprint scanner
* Input: None
* Output: \<boolean\>

## open()
To open the fingerprint scanner
* Input: None
* Output: \<boolean\>

## close()
To close the fingerprint scanner
* Input: None
* Output: \<boolean\>

## set_led(on)
To turn light on or off
* Input
 * on: \<boolean\> True for turning on the light and False for turning off the light
* Output: \<boolean\>

## get_enrolled_cnt()
To turn light on or off
* Input: None
* Output: \<integer\> The number of enrolled users

## is_finger_pressed()
To check if a finger is pressed or not
* Input: None
* Output: \<boolean\>

## change_baud(baud=115200)
To change the baud rate from 9600 to 115200 (or below)
* Input
 * baud: \<integer\> A number between 9600 and 115200

## enroll(idx)
To enroll a fingerprint with an ID
* Input
 * idx: \<integer\> An ID of the fingerprint
* Output: \<integer\> An enrolled fingerprint ID (-1 when failed)

## delete(idx=None)
To delete enrolled fingerprints
* Input
 * idx: An fingerprint ID to delete (None for deleting all enrolled fingerprints)

* Output: \<boolean\>

## identify()
To identify a fingerprint
* Input: None
* Output: \<integer\>: An identified fingerprint ID (-1 when failed to identify)
