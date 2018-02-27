package image.setgano.msblsb;

import java.io.File;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.stream.IntStream;

public class Main {

	public static void main(String[] args) throws Exception{
				char[] password = new char[] {'p','a','s','s','w','o','r','d'};// your password, possibly from JPasswordField
				//Steganography steg = new Steganography();
				SteganographyM3 stegM1 = new SteganographyM3();
				// hide the file
				//steg.setCompression(true); // enable compression
				//steg.setEncryption(true); // enable encryption
				//							image for hiding data 		//			file for hide							// output folder					// the message, that we want to hide // password
				//steg.hide(new File("D:\\Stego\\aa.jpg"), new File("D:\\Stego\\Secret\\gg.docx"), new File("D:\\Stego\\Output"),"How are you ", password);
				
				stegM1.hide(new File("D:\\Stego\\dd.jpg"), new File("D:\\Stego\\Secret\\gg.docx"),"How are you ", password);
				// extract the file
				// the stegano image 				// the output folder			// password
				//steg.reveal(new File("D:\\Stego\\Output1\\dd.png"),new File("D:\\Stego\\Decode"), password);
				
				stegM1.reveal(new File("D:\\Stego\\Output\\outputM1.png"),new File("D:\\Stego\\Decode"), password);
				
				
	}

}
