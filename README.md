## Retail

`Retail` is sth like linux command tail, and support "retail" which means one can tail a file use a pos file which saves the last read position.

## Requeriments

inotify are required.

## Installation

```
sh> make
```

## Usage

```
# for help
sh> ./tail -h 

# tail a file
sh> ./tail -f ./1.txt -p ./1.txt -s 1 -d
```
