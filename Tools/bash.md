<!--- Courtesy : https://ryanstutorials.net/bash-scripting-tutorial/bash-if-statements.php-->
<!-- Bash tricks :
https://www.tldp.org/LDP/abs/html/special-chars.html https://stackoverflow.com/questions/68372/what-is-your-single-most-favorite-command-line-trick-using-bash-->
# Bash


## Variables
### Assigning Variable
```
# DO NOT USE SPACE BEFORE OR AFTER '='
a='Hello World!' # assign 'a' to 'Hello World!' string
b=$1             # assign 'b' to the first argument passed to the script
c="William, $a"  # ' " ' allows substitution of variables
d=$(ls -la)      # assign 'd' to the command output
e=${2:-${1}}     # assign $2 to 'e', if there is none, assign $1 (${var:-default})
```
### Special Variables
Variable     | Usage
-------------|---------------
 `$0`        | the name of the script
 `$1-$9`     | arguments passed
 `$#`        | number of arguments passed
 `$@`        | all the arguments supplied to the script
 `$?`        | exit status
 `$$`        | process id
 `$USER`     | current user
 `$HOSTNAME` | current hostname
 `$SECONDS`  | number of seconds since script started
 `$RANDOM`   | returns random number
 `$LINENO`   | returns the current line number in bash script

### Exporting variables
`export var1` makes a variable available to other child processes
<br>
###### Example
###### script1.sh
```
# script1.sh
#!/bin/bash
# demonstrate variable scope 1.
var1=blah
var2=foo
# Let's verify their current value
echo $0 :: var1 : $var1, var2 : $var2
export var1
./script2.sh
# Let's see what they are now
echo $0 :: var1 : $var1, var2 : $var2
```
###### script2.sh
```
#!/bin/bash
# demonstrate variable scope 2
# Let's verify their current value
echo $0 :: var1 : $var1, var2 : $var2
# Let's change their values
var1=flop
var2=bleh
```
###### Output
```
script1.sh :: var1 : blah, var2 : foo
script2.sh :: var1 : blah, var2 :
script1.sh :: var1 : blah, var2 : foo
```

## Input
### User Input
We use `read` to read user input in Bash
```
#!/bin/bash
echo Hello, who am I talking to?
read varname
echo It\'s nice to meet you $varname
```
```
#!/bin/bash
read -p 'Username: ' uservar  # -p : prompt
read -sp 'Password: ' passvar # -s : silent
echo
echo Thankyou $uservar we now have your login details
```
```
#!/bin/bash
echo What cars do you like?
read car1 car2 car3
echo Your cars are : $car1, $car2, and $car3
```

### STDIN
```
#!/bin/bash
echo Here is a summary of the sales data:
echo ====================================
echo
cat /dev/stdin | cut -d' ' -f 2,3 | sort
```
```
user@bash : cat salesdata.txt
Fred apples 20 July 4
Susy oranges 5 July 7
Mark watermelons 12 July 10
Terry peaches 7 July 15
user@bash:
user@bash: cat salesdata.txt | ./summary
Here is a summary of the sales data:
====================================
apples 20
oranges 5
peaches 7
watermelons 12
```
or you can use `<` instead
```
#!/bin/bash
filename="$1"
while read -r line
do
    name="$line"
    echo "Name read from file - $name"
done < "$filename"
```

## Arithmetic
### let
`let` save the result to a variable
```
#!/bin/bash
let a=5+4
echo $a # 9
let "a = 5 + 4"
echo $a # 9
let a++
echo $a # 10
let "a = 4 * 5"
echo $a # 20
let "a = $1 + 30"
echo $a # 30 + first command line argument
```
### expr
`expr` print the result
```
#!/bin/bash
expr 5 + 4
expr "5 + 4"
expr 5+4
expr 5 \* $1
expr 11 % 2
a=$( expr 10 - 3 )
echo $a # 7
```

### Double Parentheses
`$((expression))` can also be used to count
```
#!/bin/bash
a=$(( 4 + 5 ))
echo $a # 9
a=$((3+5))
echo $a # 8
b=$(( a + 3 ))
echo $b # 11
b=$(( $a + 4 ))
echo $b # 12
(( b++ ))
echo $b # 13
(( b += 3 ))
echo $b # 16
a=$(( 4 * 5 ))
echo $a # 20
```

### Length of a Variable
`${#variable}` can be used to output the length of a variable
```
#!/bin/bash
# Show the length of a variable.
a='Hello World'
echo ${#a} # 11
b=4953
echo ${#b} # 4
```

## If Statement
### Tests
Operator | Descriptor
---------|-----------
`!EXPRESSION` | The EXPRESSION is false
`-n STRING` | The length of STRING is greater than zero
`-z STRING` | The length of STRING is zero (ie it its empty)
`STRING1=STRING2` | STRING1 is equal to STRING2
`STRING!=STRING2` | STRING1 is not equal to STRING2
`INT1 -eq INT2` | INT1 is numerically equal to INT2
`INT1 -gt INT2` | INT1 is numerically greater than INT2
`INT1 -lt INT2` | INT1 is numerically less than INT2
`-d FILE` | FILE (FILE is a path) exists and is a directory   
`-e FILE` | FILE exists
`-r FILE` | FILE exists and read permission is granted
`-s FILE` | FILE exists and it's size is greater than zero (ie. it is not empty)
`-w FILE` | FILE exists and write permission is granted
`-x FILE` | FILE exists and execute permission is granted

NB: `=` is a string comparison and `-eq` is a number comparison

### If
```
#!/bin/bash
# elif statements
if [ $1 -ge 18 ]
then
    echo You may go to the party.
elif [ $2 == 'yes' ]
then
    echo You may go to the party but be back before midnight.
else
    echo You may not go to the party.
fi

# Nested if statements
if [ $1 -gt 100 ]
then
    echo Hey that\'s a large number.
    if (( $1 % 2 == 0 )) # to count
    then
        echo And is also an even number.
    fi
fi
```
### Case
```
#!/bin/bash
# case example
case $1 in
  start)
    echo starting
    ;;
  stop)
    echo stoping
    ;;
  restart)
    echo restarting
    ;;
  *)
    echo don\'t know
    ;;
esac
```

### Boolean Opeartor
You can use `||` or `&&` in an if-statement
```
#!/bin/bash
# and example
if [ -r $1 ] && [ -s $1 ]
then
    echo This file is useful.
fi
```
## Loops
### For
```
#!/bin/bash
# Basic for loop
names='Stan Kyle Cartman'
for name in $names
do
    echo $name
done
echo All done
```
```
#!/bin/bash
# Basic range with steps for loop
for value in {10..0..2}
do
  echo $value
done
echo All done
```

### While
```
while_loop.sh
#!/bin/bash
# Basic while loop
counter=1
while [ $counter -le 10 ]
do
    echo $counter
    ((counter++))
done
echo All done
```
### Until
```
#!/bin/bash
# Basic until loop
counter=1
until [ $counter -gt 10 ]
do
    echo $counter
    ((counter++))
done
echo All done
```
### Select
`select` is used to make a simple options, given a list of items
```
#!/bin/bash
# A simple menu system
names='Kyle Cartman Stan Quit'
PS3='Select character: '
select name in $names
do
    if [ $name == 'Quit' ]
    then
        break
    fi
    echo Hello $name
done
echo Bye
```
Result
```
user@bash: ./select_example.sh
1) Kyle     3) Stan
2) Cartman  4) Quit
Select character: 2
Hello Cartman
Select Character: 1
Hello Kyle
Select character: 4
Bye
```

### Break
`break` is used to break a loop

### Continue
`continue` is used to skip an iteration on a loop

## Functions
You can define a function with `func_name () {}` or `function func_name {}`

```
#!/bin/bash
# Basic function
print_something1 () {
    echo Hello I am a function
}
function print_something2 {
    echo Hello I am a function
}
print_something1
print_something2
```
### Passing arguments
```
#!/bin/bash
# Passing arguments to a function
print_something () {
  echo Hello $1
}
print_something Mars
print_something Jupiter
```
### Return
`return` function gives out the exit code of the function UNLIKE other common languages
```
#!/bin/bash
# Setting a return status for a function
print_something () {
  echo Hello $1
return 5
}
print_something Mars
print_something Jupiter
echo The previous function has a return value of $?
```
One way to work around this is to use command subtitution
```
#!/bin/bash
# Setting a return value to a function
lines_in_file () {
  cat $1 | wc -l
}
num_lines=$( lines_in_file $1 )
echo The file $1 has $num_lines lines in it.
```
### Local variable
`local` keyword is used to define a variable that will be deallocated after a function is exited
```
#!/bin/bash
# Experimenting with variable scope
var_change () {
  local var1='local 1'
  echo Inside function: var1 is $var1 : var2 is $var2
  var1='changed again'
  var2='2 changed again'
}
var1='global 1'
var2='global 2'
echo Before function call: var1 is $var1 : var2 is $var2
var_change
echo After function call: var1 is $var1 : var2 is $var2
```

### Overriding Commands
You can use `command` keyword to override a function (command)
```
#!/bin/bash
# Create a wrapper around the command ls
ls () {
  command ls -lh
}
ls
```

## Output
### `>` and `>>`
`>>` appends to a file or creates the file if it doesn't exist.<br>
```
$ echo "End of directory listing" >> allmyfiles.txt
```
<br>
`>` overwrites the file if it exists or creates it if it doesn't exist. <br>
The `>` sign is used for redirecting the output of a program to something other than stdout (standard output, which is the terminal by default).
```
$ ls > allmyfiles.txt
```
### `x>&y`
You can redirect an output x to an output y

x or y   | Function
---------|----------------------
`0`      | STDIN to somewhere
`1`      | STDOUT to somewhere
`2`      | STDERR to somewhere
`&`      | All
` `      | Whatever is provided
