import java.io.*;
import java.util.Arrays;
import java.util.Scanner;


//128 Bit AES Implementation
//Student Name: Alexander Lannon
//Student Number: 7859439

public class AES {
    //Precomputed subbox and invSubBox tables used during encryption
    //Made static as they are used in multiple methods
    static int[] subBox = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

    static int[] invSubBox = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

    //Main Method
    //Takes in two parameters, the first being the name of the plaintext file, and the second being the name of the key file
    //Processes each text file to get the message and key into hexadecimal arrays
    //The arrays are of type char, in case the actual text values ever want to be printed, instead of just the hex values
    //Also calls the key generation method to calculate and store the 11 keys needed to encrypt
    //Then calls the encrypt function to encrypt the message, and the decrypt method to decrypt the message
    public static void main(String[] args){
        //Strings that store the input from the text files
        String plainText;
        String key;

        //Char arrays of values passed to the program
        char[][] keys; //Will hold all 11 keys needed to encrypt/decrypt
        char[][] state; //Holds the current state of the message at any given time

        //Checks for correct number of arguments
        if(args.length == 2) {
            //Try to open the files given
            try {
                //Reads line from each file and stores it as a corresponding string value
                BufferedReader plainTextFile = new BufferedReader(new FileReader(args[0]));
                BufferedReader keyFile = new BufferedReader(new FileReader(args[1]));
                plainText = plainTextFile.readLine();
                key = keyFile.readLine();

                //Gets starting state from given plaintext
                state = msgToArray(plainText);

                //Generates keys from the given key
                keys = keyExpansion(key);

                //Prints passed plaintext and key
                System.out.println("Plaintext:");
                printMsg(state);
                System.out.println("Key:");
                printKey(keys[0]);
                System.out.println();

                //Prints out the generated keys
                System.out.println("Key Schedule:");
                for(int i = 0; i < 11; i++){
                    printKey(keys[i]);
                }

                //Starts Encryption process
                encrypt(state, keys);

                //Starts Decryption process
                decrypt(state, keys);

                plainTextFile.close();
                keyFile.close();
            }

            //If files cannot be found, an error message is printed
            catch (Exception e){
                System.out.println(e);
            }
        }

        //Wrong number of arguments given, prints error message and exits
        else{System.out.println("ERROR: Wrong number of arguments given, expect 2 was given " + args.length);}
    }

    //ENCRYPT METHOD
    //Takes a passed message state and key matrix and encrypts it using AES
    //Prints each call to mixCols and prints final result
    //Does not return any value, but modifies passed state matrix
    public static void encrypt(char[][] state, char[][] keys){
        System.out.println("\nSTARTING ENCRYPTION PROCESS\n---------------------------");
        System.out.println("Plain Text:");
        printMsg(state);
        System.out.println();

        //XOR state with first key
        stateXOR(state, keys[0]);

        //Loops for remaining number of keys
        for(int r = 1; r < 11; r++){

            //Sbox sub and shift rows of state
            subBytes(state);
            shiftRows(state);

            //If current key number is in range [1,9], then mixCols is called
            if(r <= 9){
                mixCols(state);
                System.out.println("State after call " + r + " to mixColumns():");
                printMsg(state);
                System.out.println();
            }

            //XOR state with current key r
            stateXOR(state, keys[r]);
        }

        //Prints out final Ciphertext
        System.out.println("Ciphertext:");
        printMsg(state);
    }

    //DECRYPT METHOD
    //Takes passed message state and key matrix and decrypts the message
    //Prints each call to invMixCols and prints final result
    //Does not return any value, but modifies the passed state matrix
    public static void decrypt(char[][] state, char[][] keys){
        System.out.println("\nSTARTING DECRYPTION PROCESS\n---------------------------");
        System.out.println("Cipher Text:");
        printMsg(state);

        //Stores number of times invMixColumns() was called
        int callNum = 1;

        //Loops through every key in reverse order
        for(int r = 10; r > 0; r--){
            //XOR state with current key r
            stateXOR(state, keys[r]);

            //If current key number is in range [9,1], then invMixCols is called
            if(r <= 9){
                invMixCols(state);
                System.out.println("State after call " + callNum + " to invMixColumns():");
                printMsg(state);
                System.out.println();

                callNum++;
            }

            //Inverts row shift and inverts Sbox
            invShiftRows(state);
            invSubBytes(state);
        }

        //XOR state with final key and prints result
        stateXOR(state, keys[0]);
        System.out.println("Plain Text:");
        printMsg(state);
    }

    //SUB BYTES FUNCTIONS:
    //Each function takes in a 4x4 input array and swaps each byte value with the corresponding value
    //Value at each index is used as the index to find the value to swap to
    //subBytes() swaps the value of an input with the corresponding value in subBox
    //invSubBytes() swaps the value of an input with the corresponding value in invSubBox
    public static void subBytes(char[][] input){
        for(int row = 0; row < 4; row++){
            for(int col = 0; col < 4; col++){
                input[row][col] = (char) subBox[input[row][col]]; } } }
    public static void invSubBytes(char[][] input){
        for(int row = 0; row < 4; row++){
            for(int col = 0; col < 4; col++){
                input[row][col] = (char) invSubBox[input[row][col]]; } } }

    //KEY EXPANSION:
    //Takes in a key string of 128 bits in length
    //Generates 11 128 bit keys and returns them in a char array
    public static char[][] keyExpansion(String key){
        //Array of constants, used in key calculation
        int[] C = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
        char[] temp = new char[4];

        //2 dimensional key to store keys, row wise
        char[][] keys = new char[11][16];
        keys[0] = keyToArray(key); //Starting key K0

        //Loops through and calculates keys 1 to 11
        for(int i = 1; i < 11; i++) {
            //Temporary array to hold the starting values for the first 4 bytes of the key
            //Cyclic shift one byte to the left, then get subBox value of each byte, then XOR with constant Ci
            //Formula is Ki-1[0] ^ S(Ki-1[3] <<< 8) ^ Ci
            temp[0] = (char) (subBox[keys[i-1][13]] ^ C[i-1]);
            temp[1] = (char) subBox[keys[i-1][14]];
            temp[2] = (char) subBox[keys[i-1][15]];
            temp[3] = (char) subBox[keys[i-1][12]];

            //Ki[0]
            for (int k = 0; k < 4; k++) { keys[i][k] = (char)(keys[i-1][k] ^ temp[k]); }
            //Ki[1]
            for (int k = 4; k < 8; k++) { keys[i][k] = (char)(keys[i-1][k] ^ keys[i][k-4]); }
            //Ki[2]
            for (int k = 8; k < 12; k++) { keys[i][k] = (char)(keys[i-1][k] ^ keys[i][k-4]); }
            //Ki[3]
            for (int k = 12; k < 16; k++) { keys[i][k] = (char)(keys[i-1][k] ^ keys[i][k-4]); }
        }

        //Returns 11 x 16 char array containing 11 keys
        return keys;
    }

    //SHIFT ROW FUNCTIONS:
    //Performs a cyclic on each row of a passed state matrix
    //shiftRows() shifts each a number of spots equal to its row number to the left
    //invShiftRows() shifts each a number of spots equal to its row number to the right
    public static void shiftRows(char[][] state){
        char[] temp; //Temp array to hold values before swapping

        //Loops through each row
        for(int row = 1; row < 4; row++) {
            //Copies values at current row into temp array
            temp = Arrays.copyOf(state[row], 4);

            //Shifts row to the left equal to the current row number
            //Mod 4 is used to make shift cyclic
            for (int k = 0; k < 4; k++) {
                state[row][k] = temp[(k + row) % 4];
            }
        }
    }
    public static void invShiftRows(char[][] state){
        char[] temp;//Temp array to hold values before swapping

        //Loops through each row
        for(int row = 1; row < 4; row++) {
            //Copies values at current row into temp array
            temp = Arrays.copyOf(state[row], 4);

            //Shifts row to the right equal to the current row number
            //Since this is in the right direction, subtraction cannot just be used as index could be negative
            //4 is added to each index in temp as well as mod 4 to make shift cyclic
            for (int k = 0; k < 4; k++) {
                state[row][k] = temp[(k - row + 4) % 4];
            }
        }
    }

    //MIX COLUMN FUNCTIONS:
    //Are passed a given state array and transform it through matrix multiplication
    //mixCols() goes one way and is used during encryption
    //invMixCols() goes the other way and does the inverse of the other
    //mixCols() Multiplies each column of a passed state matrix by the matrix:
    //  02 03 01 01
    //  01 02 03 01
    //  01 01 02 03
    //  03 01 01 02
    // in GF 256
    public static void mixCols(char[][] state){
        char[] temp = new char[4];

        //Loops trough each column of the given state matrix
        for(int c = 0; c < 4; c++) {
            //Gets current column
            copyCol(state, temp, c);

            //Calculates each row of the matrix multiplication in GF 256
            state[0][c] = (char) (multGF256(temp[0], 2) ^ multGF256(temp[1], 3) ^ temp[2] ^ temp[3]);
            state[1][c] = (char) (temp[0] ^ multGF256(temp[1], 2) ^ multGF256(temp[2], 3) ^ temp[3]);
            state[2][c] = (char) (temp[0] ^ temp[1] ^ multGF256(temp[2], 2) ^ multGF256(temp[3], 3));
            state[3][c] = (char) (multGF256(temp[0], 3) ^ temp[1] ^ temp[2] ^ multGF256(temp[3], 2));
        }
    }

    //invMixCols() Multiplies each column of a passed state matrix by the matrix:
    //  0e 0b 0d 09
    //  09 0e 0b 0d
    //  0d 09 0e 0b
    //  0b 0d 09 0e
    // in GF 256
    public static void invMixCols(char[][] state){
        char[] temp = new char[4];

        //Loops trough each column of the given state matrix
        for(int c = 0; c < 4; c++) {
            //Gets current column
            copyCol(state, temp, c);

            //Calculates each row of the matrix multiplication in GF 256
            state[0][c] = (char) (multGF256(temp[0], 0x0e) ^ multGF256(temp[1], 0x0b) ^ multGF256(temp[2], 0x0d) ^ multGF256(temp[3],0x09));
            state[1][c] = (char) (multGF256(temp[0], 0x09) ^ multGF256(temp[1], 0x0e) ^ multGF256(temp[2], 0x0b) ^ multGF256(temp[3],0x0d));
            state[2][c] = (char) (multGF256(temp[0], 0x0d) ^ multGF256(temp[1], 0x09) ^ multGF256(temp[2], 0x0e) ^ multGF256(temp[3],0x0b));
            state[3][c] = (char) (multGF256(temp[0], 0x0b) ^ multGF256(temp[1], 0x0d) ^ multGF256(temp[2], 0x09) ^ multGF256(temp[3],0x0e));
        }
    }

    //Copies the column of a given 2d matrix into a 1d target matrix
    //Does not return any value, changes are made directly to the target array
    public static void copyCol(char[][] source, char[] target, int col){
        target[0] = source[0][col];
        target[1] = source[1][col];
        target[2] = source[2][col];
        target[3] = source[3][col];
    }

    //Multiplies a given integer input by a given type in GF 256
    //Only values of 0x02, 0x03, 0x0e, 0x0b, 0x0d 0x09 can be multiplied
    //Returns the product of the multiplication, or -1 if the type is incorrect
    public static int multGF256(int input, int type){
        int ans = -1;

        //Temp values used during calculation
        int temp1;
        int temp2;
        int temp3;

        //input * 0x02
        if(type == 2){ ans = overflow(input << 1); }
        //input * 0x03
        else if(type == 3){ ans = (overflow(input << 1) ^ input); }
        //input * 0x0e
        else if(type == 0x0e){
            temp1 = overflow(input << 1); //0x02
            temp2 = overflow(temp1 << 1); //0x04
            temp3 = overflow(temp2 << 1); //0x08
            ans = temp1 ^ temp2 ^ temp3;
        }
        //input * 0x0b
        else if(type == 0x0b){
            temp1 = overflow(input << 1); //0x02
            temp2 = overflow(temp1 << 1); //0x04
            temp3 = overflow(temp2 << 1); //0x08
            ans = temp3 ^ temp1 ^ input;
        }
        //input * 0x0d
        else if(type == 0x0d){
            temp1 = overflow(input << 1); //0x02
            temp2 = overflow(temp1 << 1); //0x04
            temp3 = overflow(temp2 << 1); //0x08
            ans = temp3 ^ temp2 ^ input;
        }
        //input * 0x09
        else if(type == 0x09){
            temp1 = overflow(input << 1); //0x02
            temp2 = overflow(temp1 << 1); //0x04
            temp3 = overflow(temp2 << 1); //0x08
            ans = temp3 ^ input;
        }

        //Product is returned
        return ans;
    }

    //Checks if there is overflow for a given integer in GF256
    //If so overflows number back around to within GF256 and returns it
    //Otherwise the input number is returned with no changes
    public static int overflow(int in){
        int ans = in;
        if(ans > 255) { ans = (ans % 256) ^ 0x1b; }
        return ans;
    }

    //Takes in a current state and a key to XOR with column wise
    public static void stateXOR(char[][] state, char[] key){
        byte b = 0; //Stores which byte of the key is being processed

        for(int col = 0; col < 4; col++){
            for(int row = 0; row < 4; row++){
                state[row][col] = (char) (state[row][col] ^ key[b]);
                b++;
            }
        }
    }

    //Puts given 16 byte message into a 4 x 4 array form
    //Chars are stored as hexadecimal values
    //Input message must only be 16 hexadecimal values long
    public static char[][] msgToArray(String input){
        char[][] out = new char[4][4]; //Output array
        Scanner scan; //Scanner to split input on spaces

        //Checks to make sure input message is 16bytes long by counting the number of spaces in the string
        //If shorter than 16 bytes the string is padded with zeros on the end
        long spaceCount = input.chars().filter(c -> c == (int) ' ').count();
        if(spaceCount < 15){
            for(long i = spaceCount; i < 15; i++){
                input = input.concat(" 0");
            }

        }
        scan = new Scanner(input); //Gives updated input to scanner

        //Loops through and puts 4 bytes in each column of the output array
        //Splits string on each space and parses each as a hex value
        for(int col = 0; col < 4; col++){
            for (int row = 0; row < 4; row++) {
                out[row][col] = (char) Integer.parseInt("" + scan.next(), 16);

            }
        }
        scan.close();

        return out;
    }

    //Takes a given String key and turns it into a char array of length 16
    //Chars are stored as hexadecimal values
    //Key must only be 16 hexadecimal values long
    public static char[] keyToArray(String k){
        char[] out = new char[16]; //Output array
        Scanner scan = new Scanner(k); //Scanner to split key on spaces

        //Loops through each hex byte in string by splitting on the spaces from the input k
        //Parses each string segment in base 16 and stores it in the out array
        for(int i = 0; i < 16; i++){
            out[i] = (char) Integer.parseInt("" + scan.next(),16);
        }
        scan.close();

        return out;
    }

    //Prints the current values in the message array in hexadecimal
    public static void printMsg(char[][] message){
        for(int row = 0; row < 4; row++) {
            for(int col = 0; col < 4; col++) {
                System.out.print("" + String.format("%02x", (int)message[col][row]) + " ");

            }
        }
        System.out.println();
    }

    //Prints the current values of the key in 32bit hexadecimal
    public static void printKey(char[] key){
        for(int i = 0; i < 16; i++){
            System.out.printf("%02x", (int) key[i]);
            if(i != 15 && i%4 == 3){System.out.print(",");}
        }
        System.out.println();
    }
}
