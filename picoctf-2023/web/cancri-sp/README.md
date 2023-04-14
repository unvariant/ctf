# cancri-sp
Points: 500

**NOTE**: we did not solve this challenge these are just some thoughts

This problem was very interesting, and involved a heap overflow bug in a mojom. A mojom is a chrome feature that
allows javascript to call native modules written in c++. We found the heap overflow bug but could not determine how
to exploit it, definitely will try to learn more about these kind of chromium heap challs.

There was an unintended solution because the challenge author did not write their starting bash script correctly
and it was vulnerable to flag injection.

Somebody who did not cheese the challenge mentioned spraying the heap with javascript blobs in order to get a heap
leak and eventually a shell.