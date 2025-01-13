### Usage
Create a `functions.txt` file in the same directory as the compiled executable. This file should contain the function names to be hashed, with one function name per line.

Example `functions.txt`:
   ```
    WebSocketCreateClientHandle
    WebSocketBeginClientHandshake
    WebSocketEndClientHandshake
    WebSocketSend
    WebSocketDeleteHandle

   ```
Run the compiled executable. The output will be the hashed values of the function names, displayed in the console.

For the functions above,  tool will output:
   ```
    Hash for WebSocketCreateClientHandle: 0x0d7ba225
    Hash for WebSocketBeginClientHandshake: 0xe40f3ecf
    Hash for WebSocketEndClientHandshake: 0x59e188cf
    Hash for WebSocketSend: 0x24ea587e
    Hash for WebSocketDeleteHandle: 0xab65ac9d

   ```
