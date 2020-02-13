# Table of Contents
+ [EXT2 File System](#EXT2FileSystem)
+ [How to use](#Howtouse)
+ [Contributors](#Contributors)
+ [Run GDBGUI](#RunGDBGUI)

# BLANK 1

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank

blank
# EXT2 File System <a name="EXT2FileSystem"></a>

# BLANK 2

blank

blank

blank

blank

blank

blank

blank

blank

blank



## How to use <a name="Howtouse"></a>


## Contributors


## Run GDBGUI <a name="RunGDBGUI"></a>

1. compile using '-g' option

```
gcc -g -o file_name files
```

2. start gdb server

```
gdbserver localhost:port /file_path/file_name
```

3. another terminal

```
gdbgui -g gdb-multiarch
```

4. in gdbgui window

```
file /file_path/file_name

tartget remote:port
```


## 연습장

###  이것은 글자 크기

이것은 본문

>이것은 인용

**이것은 굵게**

***이것은 기울임***

~~이것은 취소선~~



```c
// 이것은 코드

typedef struct {
    EXT2_FILESYSTEM *fs;
    EXT2_DIR_ENTRY entry;
    EXT2_DIR_ENTRY_LOCATION location;
} EXT2_NODE;

int main(int argc, char *argv[]) 
{
    EXT2_NODE wow;

    return 0;
}
```