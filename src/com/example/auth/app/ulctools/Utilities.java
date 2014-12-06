package com.example.auth.app.ulctools;

/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */

/**
 * Compatibility class to make Desktop versions of Ticket class methods compatible with the Android application.
 */
public class Utilities {
    Commands ul;


    public Utilities(Commands ul) {
        this.ul = ul;
    }
    /**
     * Try to erase card content from page 4 to page 39.
     *
     * @return boolean value of success
     */
    public boolean eraseMemory() {
        Reader.erase(false);
        return true;
    }

    /**
     * Read the card memory to a given array with authentication or without authentication.
     *
     * @return byte array where the data is stored
     */
    public byte[] readMemory() {
        byte[] memory = new byte[192];
        readPages(0, 44, memory, 0);
        return memory;
    }


    /**
     * Read card memory from starting page for defined amount of pages
     *
     * @param startPage            start page of read
     * @param numberOfPages        how many pages to read
     * @param destination          where to store received data
     * @param destinationStartByte at what point to store received data
     * @return boolean value of success
     */
    public boolean readPages(int startPage, int numberOfPages, byte[] destination, int destinationStartByte) {
        // We always read and write one 4-byte page at a time.
        // The address is the number 0...39 of the 4-byte page.
        for (int i = 0; i < numberOfPages; i++) {
            boolean status = ul.readBinary(startPage + i, destination,
                    destinationStartByte + i * 4);
            if (!status) {
                return false;
            }
        }
        return true;

    }

    /**
     * Write input byte array on card
     *
     * @param srcBuffer     byte array
     * @param srcPos        starting point of data to write
     * @param startPage     first page on card to write data
     * @param numberOfPages how many pages to write
     * @return boolean value of success
     */
    public boolean writePages(byte[] srcBuffer, int srcPos, int startPage, int numberOfPages) {
        boolean status;
        // We always read and write one 4-byte page at a time.
        // The address is the number 0...39 of the 4-byte page.
        for (int i = 0; i < numberOfPages; i++) {
            status = ul.writeBinary(startPage + i, srcBuffer, srcPos + 4
                    * i);
            if (!status) {
                return false;
            }
        }
        return true;
    }


    /**
     * Lock pages.
     * Locking is limited to pages 4-39 in this assignment.
     * <p/>
     * Locking pages 4-15 is done by giving the page as a parameter, but
     * pages 16-39 (due Ultralight C to specification) are locked in 4 page series:
     * 16-19
     * 20-23
     * 24-27
     * 28-31
     * 32-35
     * 36-39
     * To lock any of the series give the first page as parameter, giving 16 will lock pages 16-19.
     * <p/>
     * No blocking functionality.
     * Uses Reader class in actual card interfacing.
     *
     * @param pageNumber page to lock
     * @return boolean value of success
     */
    // Lock a page (not a good idea when practicing)
    public boolean lockPage(int pageNumber) {
        if (pageNumber < 4 || pageNumber > 36)
            return false;
        return Reader.lockPage(pageNumber);
    }

    /**
     * Authenticate card with given key in stored in byte array
     *
     * @param key byte array that contains the key
     * @return boolean value of success
     */
    public boolean authenticate(byte[] key) {
        return Reader.authenticate(key, true);
    }

    public boolean setAuth0(int page) {
        return Reader.setAuth0(page, false);
    }

    public boolean setAuth1(boolean noRead) {
        return Reader.setAuth1(noRead, false);
    }

    public boolean changeKey(byte[] key) {
        return Reader.writeKey(key, false);
    }

    // Write selected pages from a card memory image into the card.
    public boolean writeMemory(byte[] memoryImage, int startPage,
                               int numberOfPages) {
        return writePages(memoryImage, startPage * 4, startPage, numberOfPages);
    }

    // Zero a single page of the card. (Cannot be used for pages 0...3).
    public boolean erasePage(int pageNumber)  {
        byte[] zeroPage = { 0x00, 0x00, 0x00, 0x00 };
        boolean status = ul.writeBinary(pageNumber, zeroPage, 0);
        return status;
    }
}
