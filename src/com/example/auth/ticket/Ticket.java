package com.example.auth.ticket;

import com.example.auth.app.fragments.TicketFragment;
import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Dump;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Date;

/**
 * TODO: Complete the implementation of this class. Most of the code are
 * already implemented. You will need to change the keys, design and implement 
 * functions to issue the ticket and use it.
 * 
 * Method bodies compatible with desktop Java version, but the methods throw different exceptions so only the body can be copied straight!
 *
 */
public class Ticket {

	private static byte[] authenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16 byte long key
    public static byte[] data = new byte[192];
    private static TicketMac macAlgorithm;
    private static Utilities utils;
    private static Commands ul;
    private static int secsMonth = 2628000;
   
    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;
    public static Boolean isAuthenticated = false;
    
    public static String infoToShow; // Use this to show messages in Log and in Tap mode
    

    // Define a page-4 application tag to use for the ticket application.
    // It will be written to card memory page 4 and used to identify the
    // ticket application.
    public byte[] applicationTag = "TCKT".getBytes();
    private static final int usedMacLength = 2; // Mac length in 4-byte pages.

    public Ticket() throws GeneralSecurityException {
        macAlgorithm = new TicketMac();
        
        //TODO: Change hmac key according to your need
        byte[] hmacKey = new byte[16];
        macAlgorithm.setKey(hmacKey);
        
        ul = new Commands();
        utils = new Utilities(ul);
    }

    // Do not copy this method to Java version
    public static void dump() {
    	if (isAuthenticated == false) {
    		utils.authenticate(authenticationKey);
    		isAuthenticated = true;
    		Reader.readMemory(data, false, false);
            TicketFragment.ticket_dump.setText(Dump.hexView(data, 0));
    	} else {
    		Reader.readMemory(data, false, false);
            TicketFragment.ticket_dump.setText(Dump.hexView(data, 0));
    	}
    }

    // Format the card to be used as a ticket.
    public boolean format() {
        boolean status;
        
        utils.authenticate(authenticationKey);
        
        // Zero the card memory. Fails is any of the pages is locked.
        status = utils.eraseMemory();
        if (!status)
            return false;

        // Write the application tag to memory page 4.
        status = ul.writeBinary(4, applicationTag, 0);

        if (!status)
            return false;
        // In a real application, we probably would lock some pages here,
        // but remember that locking pages is irreversible.

        // Check the format.
        if (!checkFormat()) {
            return false;
        }

        return true;
    }

    // Check that the card has been correctly formatted.
	protected boolean checkFormat() {
		// Read the card contents and check that all is ok.
	    byte[] memory = utils.readMemory();
	    if (memory == null)
	        return false;
	    
	    // Check the application tag.
	    for (int i = 1; i < 4; i++)
	        if (memory[4 * 4 + i] != applicationTag[i])
	            return false;
	    
	    // Check zeros. Ignore page 36 and up because of the safe mode.
	    for (int i = 5 * 4; i < 36 * 4; i++)
	        if (memory[i] != 0)
	            return false;
	    
	    // Check that the memory pages 4..39 are not locked.
	    // Lock 0: Check lock status for pages 4-7
	    if (memory[2 * 4 + 2] != 0) 
	        return false;
	    // Lock 1: 
	    if (memory[2 * 4 + 3] != 0)
	        return false;
	    // Lock 2:
	    if (memory[40 * 4] != 0)
	    		return false;
	    // Lock 1:
	    if (memory[40 * 4 + 1] != 0)
	    		return false;
	        
	    return true;
	}

    // Issue new tickets.
    public boolean issue(int expiryTime, int uses) throws GeneralSecurityException {
    	utils.authenticate(authenticationKey);
    	
    	if (!checkFormat()) {
            System.err.print("Format error");
            return false;
        }
        // Dummy ticket with just an HMAC. You need to implement the rest.
        
        // Proper ticketing.
        
        // Write the expirity date to page 7
        utils.writePages(ByteBuffer.allocate(4).putInt(expiryTime).array(), 0, 7, 1);
        
        // Write the remaining uses to page 8
        utils.writePages(ByteBuffer.allocate(4).putInt(uses).array(), 0, 8, 1);
        
        // Currently it only reads first 5 pages.
        byte[] dataOnCard = new byte[5 * 4];
		utils.readPages(0, 5, dataOnCard, 0);
		
		// ignore locks and OTP bits
		for (int ig = 0; ig < 6; ig ++){
			dataOnCard[10+ig] = 0;
		}
		
		byte[] mac = macAlgorithm.generateMac(dataOnCard);
		// We only use 8 bytes (64 bits) of the MAC.
		utils.writePages(mac, 0, 5, usedMacLength);
        
        // Changes the authentication key
        utils.changeKey(authenticationKey);
        
        // Sets Auth0 and Auth1 settings
        utils.setAuth0(3);//Authentication is required from page 3
        utils.setAuth1(true);// true: Authentication is required for read & write; false: Authentication is require for write only
        
        return true;
    }

    // Use the ticket once.
    public void use(int currentTime) throws GeneralSecurityException {
    	
    	utils.authenticate(authenticationKey);
    		// Dummy ticket use that validates only the HMAC. You need to implement the rest.    		
    	
    	// TODO: Create methods to read from card and store to the card
    	// need to update the new remaining uses of the card.
    	
    	// Retrieve the expiry time from card at page 7
    	byte[] expiryTimeByte = new byte[4];
    	utils.readPages(7, 1, expiryTimeByte, 0);
    	expiryTime = ByteBuffer.wrap(expiryTimeByte).getInt();
    	
    	// Retrieve the remaining uses from the card at page 8
    	byte[] remainingUsesByte = new byte[4];
    	utils.readPages(8, 1, remainingUsesByte, 0);
    	remainingUses = ByteBuffer.wrap(remainingUsesByte).getInt();
    			
        //TODO: Implement proper ticketing.
    	isValid = true;
        if (expiryTime < currentTime) {
        	infoToShow = "Ticket Expired!";
        	isValid = false;
        }else if (remainingUses == 0) {
        	infoToShow = "No more rides available";
        	isValid = false;
        }else if (isValid()){
	    	// This string will be shown after ticket is used in test mode. Make
	        // your own info string.
	        infoToShow = "Ticket Valid";
	        isValid = true;
	        //expiryTime = 0;
	        remainingUses--;
	        
	        // Write the remaining uses to page 8
	        
	        utils.writePages(ByteBuffer.allocate(4).putInt(remainingUses).array(), 0, 8, 1);

	        byte[] dataOnCard = new byte [5 * 4];
    		byte[] macOnCard = new byte [2 * 4];
    		utils.readPages(0, 5, dataOnCard, 0);
    		utils.readPages(5, usedMacLength, macOnCard, 0);
    		
    		// ignore locks and OTP bits
    		for (int ig = 0; ig < 6; ig ++){
    			dataOnCard[10+ig] = 0;
    		}
    		byte[] mac = macAlgorithm.generateMac(dataOnCard);
    		// We only use 8 bytes (64 bits) of the MAC.
    		for (int i = 0; i < usedMacLength*4; i++){
    			if (macOnCard[i] != mac[i]) {
    				infoToShow = "Invalid Ticket";
	    			isValid = false;
	    		}
    		}
        }
        
        if (!isValid)
        		System.err.print(infoToShow); 
    }
    
    // After validation, get ticket status: was it valid or not?
    public boolean isValid() {
        return isValid;
    }

    // After validation, get the number of remaining uses.
    public int getRemainingUses() {
        return remainingUses;
    }

    // After validation, get the expiry time.
    public int getExpiryTime() {
        return expiryTime;
    }

}