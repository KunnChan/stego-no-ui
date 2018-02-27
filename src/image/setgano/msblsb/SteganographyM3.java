package image.setgano.msblsb;

import java.awt.Graphics2D;
import java.awt.Transparency;
import java.awt.color.ColorSpace;
import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.ComponentColorModel;
import java.awt.image.DataBuffer;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.awt.image.WritableRaster;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.imageio.ImageIO;

public class SteganographyM3 {

	private final String FINGERPRINT_MESSAGE = "MIV1";
	private int offset;
	private int width;
	private int height;
	private byte[] carrier;
	private String hiddenMessage;

	private final String HYBRID_ZERO = "00";
	
	public String getDecodedMessage() {
		return hiddenMessage;
	}

	/**
	 *
	 * @param imageFile
	 *            the carrier images
	 * @param secretFile
	 *            absolute path to the secret file
	 * @param outputDir
	 *            path to save the steg file
	 * @param message
	 *            message to hide, with the secret file
	 * @param password
	 *            password to encrypt the secret file and message, ONLY if
	 *            encryption enabled
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public BufferedImage hide(File imageFile, File secretFile, String message, char[] password) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			IllegalStateException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		if (secretFile == null) {
			throw new FileNotFoundException("");
		}
		if (message == null) {
			message = "";
		}

		System.out.println("The system start hiding process...");
		byte[] payload = getBytes(secretFile);
		byte[] fingerprinMsg = FINGERPRINT_MESSAGE.getBytes();
		String sectretFname = secretFile.getName();
		int payloadSize = payload.length;
		int freeSpaceInCarrier = 0;
		int _bytesWritten;
		int payloadOffset = 0;
		int fnameLen = sectretFname.length();

		payload = addMessageToPayload(payload, message.getBytes());
		payloadSize += message.getBytes().length;

		offset = 0;
		_bytesWritten = 0;
		carrier = convertImageToRGBPixels(imageFile);
		
		int pwlength = password.length;

		freeSpaceInCarrier = carrier.length / 8;
		// System.out.println("FreeSpace In Carrier: " + freeSpaceInCarrier);
		freeSpaceInCarrier -= encode(fingerprinMsg, 4, 0);
		
		freeSpaceInCarrier -= encode(String.valueOf(pwlength).getBytes(), 1, 0); // encode the password length
		
		freeSpaceInCarrier -= encode(new String(password).getBytes(), pwlength, 0); // encode the password

		freeSpaceInCarrier -= encode(getBytes(payloadSize), 4, 0);

		freeSpaceInCarrier -= encode(getBytes(fnameLen), 4, 0);

		freeSpaceInCarrier -= encode(sectretFname.getBytes(), sectretFname.getBytes().length, 0);

		freeSpaceInCarrier -= encode(getBytes(message.getBytes().length), 4, 0);

		if (freeSpaceInCarrier < payloadSize) {
			_bytesWritten = encode(payload, freeSpaceInCarrier, payloadOffset);
		} else {
			_bytesWritten = encode(payload, payloadSize, payloadOffset);
		}
		freeSpaceInCarrier -= _bytesWritten;
		payloadSize -= _bytesWritten;
		payloadOffset += _bytesWritten;

		 ImageIO.write(convertRGBPixelsToImage(carrier), "png", new File("D:\\Stego\\Output\\outputM1.png"));

		if (payloadSize > 0) {
			throw new IllegalArgumentException("Not enough cover images");
		}
		System.out.println("Hiding process completed.");
		return convertRGBPixelsToImage(carrier);
	}

	public File saveFile(File outputFile) throws IOException {

		ImageIO.write(convertRGBPixelsToImage(carrier), "jpg", outputFile);
		return outputFile;
	}

	/**
	 * encodes the #bytesToWrite bytes payload into the carrier image starting from
	 * #payloadOffset
	 * 
	 * @param payload
	 *            to hide in the carrier image
	 * @param bytesToWrite
	 *            number of bytes to write
	 * @param payloadOffset
	 *            a pointer in the payload byte array indicating the position to
	 *            start encoding from
	 * @return number of bytes written
	 */
	private int encode(byte[] payload, int bytesToWrite, int payloadOffset) {
		int bytesWritten = 0;
		for (int i = 0; i < bytesToWrite; i++, payloadOffset++) {
			int payloadByte = payload[payloadOffset];
			bytesWritten++;
			for (int bit = 7; bit >= 0; --bit, ++offset) {
				// get first bit by bit of char
				int b = (payloadByte >>> bit) & 1;
				byte carrierByte = carrier[offset];
				String carrierByteStr = Integer.toBinaryString(carrierByte);
				String carrierLast8Bits = "";
				String first24bits = "";
				if (carrierByteStr.length() <= 8) {
					// for positive sign value
					int len = carrierByteStr.length();
					String zeroAppend = "";
					for (int index = len; index < 8; index++) {
						zeroAppend += "0";
					}
					carrierLast8Bits = zeroAppend + carrierByteStr;
				} else {
					// for negative values
					carrierLast8Bits = carrierByteStr.substring(24);
					first24bits = carrierByteStr.substring(0, 24);
				}
				// System.out.println("Offset "+ offset);

				String middleHybrid = carrierLast8Bits.charAt(3) + "" + carrierLast8Bits.charAt(4);

				String final8bits = "";

				if (HYBRID_ZERO.equals(middleHybrid)) {
					// MSB
					String first = carrierLast8Bits.substring(0, 1);
					String last6bits = carrierLast8Bits.substring(2, 8);
					final8bits = first + b + last6bits;
					
				} else {
					// LSB
					String first7bits = carrierLast8Bits.substring(0, 7);
					final8bits = first7bits + b;
				}
				String finalbits = first24bits + final8bits;

				byte bval = new BigInteger(finalbits, 2).byteValue();

				try {
					carrier[offset] = bval;
				} catch (ArrayIndexOutOfBoundsException aiobe) {
					// System.err.println(aiobe.getMessage());
				}
			}
		}
		return bytesWritten;
	}

	/**
	 * decodes #bytesToRead bytes from the carrier
	 * 
	 * @param carrier
	 * @param bytesToRead
	 * @return
	 */
	private byte[] decode(byte[] carrier, int bytesToRead) {
		byte[] _decode = new byte[bytesToRead];
		for (int i = 0; i < _decode.length; ++i) {
			StringBuffer resultBits = new StringBuffer();
			for (int bit = 0; bit < 8; ++bit, ++offset) {
				try {
					byte carrierBits = carrier[offset];
					String stegoStr = Integer.toBinaryString(carrierBits);

					String stegoLast8Bits = "";
					if (stegoStr.length() <= 8) {
						// for positive sign value
						int len = stegoStr.length();
						String zeroAppend = "";
						for (int index = len; index < 8; index++) {
							zeroAppend += "0";
						}
						stegoLast8Bits = zeroAppend + stegoStr;
					} else {
						// for negative values
						stegoLast8Bits = stegoStr.substring(24);
					}
					// System.out.println("Offset "+ offset);

					String middleHybrid = stegoLast8Bits.charAt(3) + "" + stegoLast8Bits.charAt(4);

					String resultBit = "";

					if (HYBRID_ZERO.equals(middleHybrid)) {
						// MSB
						resultBit = stegoLast8Bits.substring(1, 2);
					} else {
						// LSB
						resultBit = stegoLast8Bits.substring(7);
					}
					resultBits.append(resultBit);

				} catch (ArrayIndexOutOfBoundsException aiobe) {
					// System.err.println("OK" + aiobe.getMessage());
				}
			}
			byte bval = new BigInteger(resultBits.toString(), 2).byteValue();
			_decode[i] = bval;

		}
		return _decode;
	}

	/**
	 * Appends the message to the end of the payload.
	 * 
	 * @param payload
	 *            append the message to this payload
	 * @param msgBytes
	 *            the message to append
	 * @return payload + message
	 */
	private byte[] addMessageToPayload(byte[] payload, byte[] msgBytes) {
		int totalSize = payload.length + msgBytes.length;
		byte[] _payload = new byte[totalSize];
		for (int i = 0; i < payload.length; i++) {
			_payload[i] = payload[i];
		}
		for (int i = 0; i < totalSize - payload.length; i++) {
			_payload[i + payload.length] = msgBytes[i];
		}
		return _payload;
	}

	/**
	 * Extracts the secret file fom the provided steg image(s)
	 * 
	 * @param stegoImage
	 *            the steg images
	 * @param outDir
	 *            directory to place the extracted secret file
	 * @param password
	 *            password to decrypt the secret file and message, ONLY if the
	 *            payload was encrypted
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	@SuppressWarnings("resource")
	public String[] reveal(File stegoImage, File outDir, char[] password) throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalStateException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		byte payload[] = null;
		byte[] tmp = null;
		int payloadRemaining = 0;
		int fnameSize = 0;
		int payloadSize = 0;
		String fname = null;
		int msgLen = 0;
		int bytesToDecodeFromCarrier = 0;
		System.out.println("The system start decrypt data...");
		ArrayList<byte[]> payloadData = new ArrayList<byte[]>();
		FileOutputStream fOutStream;
		offset = 0;
		carrier = convertImageToRGBPixels(stegoImage);
		if (!isStegnographed(carrier)) {
			System.out.println("The input image is not steganographed image.");
			// continue;
			String [] fail = {"0", "Your input image is not Stegano Image [not data hided image]"};
			return fail;
		}
		bytesToDecodeFromCarrier = carrier.length / 8 - 4;// - 4 bcoz we have already decoded the fingerprint
		
		//read the password length
		tmp = new byte[1];
		String pwlengthStr = null;
		tmp = decode(carrier, 1);
		pwlengthStr = new String(tmp);
		Integer pwlength = Integer.parseInt(pwlengthStr);
		
		bytesToDecodeFromCarrier -= 1; // -1 for pw length
		
		if(!isAutorized(carrier, password, pwlength)) {
			System.out.println("Access denined.. you have entered wrong password");
			String [] fail = {"0", "You are not autorized or you have enterd wrong password"};
			return fail;
		}
		
		bytesToDecodeFromCarrier -=pwlength;	// -4 bcoz we have already decoded the password
		
		tmp=null;
		tmp = decode(carrier, 4); // extracting the payload size
		payloadSize = toInteger(tmp);
		payloadRemaining = payloadSize;
		bytesToDecodeFromCarrier -= 4;
	
		tmp = null;
		tmp = decode(carrier, 4); // extracting the size of the filename
		fnameSize = toInteger(tmp);
		bytesToDecodeFromCarrier -= 4;

		tmp = null;
		tmp = decode(carrier, fnameSize);
		bytesToDecodeFromCarrier -= fnameSize;
		fname = new String(tmp);

		tmp = null;
		tmp = decode(carrier, 4);
		msgLen = toInteger(tmp);
		// System.out.println("Message Length " + msgLen);
		bytesToDecodeFromCarrier -= 4;
		if (payloadRemaining > bytesToDecodeFromCarrier) {
			payload = decode(carrier, bytesToDecodeFromCarrier);
			payloadRemaining = payloadRemaining - bytesToDecodeFromCarrier;
		} else {
			payload = decode(carrier, payloadRemaining);
			payloadRemaining = payloadRemaining - payloadRemaining;
		}
		payloadData.add(payload);

		if (payloadRemaining > 0) {
			throw new IllegalArgumentException("Some Stego Files missing!");
		}
		String outputFilePath = outDir + "\\" + fname;
		fOutStream = new FileOutputStream(outputFilePath);
		if (!payloadData.isEmpty()) {
			byte[] secretData = new byte[payloadSize];
			byte[] message;// = new byte[msgLen];
			byte[] secretFile;// = new byte[payloadSize - msgLen];
			int ptr = 0;
			for (int i = 0; i < payloadData.size(); i++) {
				byte[] tmpArray = payloadData.get(i);
				for (int j = 0; j < tmpArray.length; j++, ptr++) {
					secretData[ptr] = tmpArray[j];
				}
			}

			message = new byte[msgLen];
			secretFile = new byte[payloadSize - msgLen];
			// System.out.println("Data Extracted!!!");
			for (int i = 0; i < payloadSize - msgLen; i++) {
				secretFile[i] = secretData[i];
			}
			// System.out.println("Got the File");
			for (int j = 0; j < (msgLen); j++) {
				message[j] = secretData[j + (payloadSize - msgLen)];
			}
			hiddenMessage = new String(message);
			System.out.println(hiddenMessage);
			fOutStream.write(secretFile);
		}
		String[] obj = {"1", outputFilePath, hiddenMessage };
		System.out.println("System completed.");
		return obj;
	}

	/**
	 * Converts a byte array with RGB pixel values to a bufferedImage
	 * 
	 * @param carrier
	 *            byte array of RGB pixels
	 * @return BufferedImage
	 */
	private BufferedImage convertRGBPixelsToImage(byte[] carrier) {
		ColorSpace cs = ColorSpace.getInstance(ColorSpace.CS_sRGB);
		int[] nBits = { 8, 8, 8 };
		int[] bOffs = { 2, 1, 0 }; // band offsets r g b
		int pixelStride = 3; // assuming r, g, b, skip, r, g, b, skip..
		ColorModel colorModel = new ComponentColorModel(cs, nBits, false, false, Transparency.OPAQUE,
				DataBuffer.TYPE_BYTE);
		WritableRaster raster = Raster.createInterleavedRaster(new DataBufferByte(carrier, carrier.length), width,
				height, width * 3, pixelStride, bOffs, null);

		return new BufferedImage(colorModel, raster, false, null);
	}

	/**
	 * Converts an Image to RG pixel array
	 * 
	 * @param filename
	 *            image to convert
	 * @return byte array
	 * @throws IOException
	 */
	private byte[] convertImageToRGBPixels(File filename) throws IOException {
		BufferedImage image = ImageIO.read(filename);
		width = image.getWidth();
		height = image.getHeight();
		BufferedImage clone = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
		Graphics2D graphics = clone.createGraphics();
		graphics.drawRenderedImage(image, null);
		graphics.dispose();
		image.flush();
		WritableRaster raster = clone.getRaster();
		DataBufferByte buff = (DataBufferByte) raster.getDataBuffer();
		return buff.getData();
	}

	/**
	 * Converts a byte array to int
	 * 
	 * @param b
	 *            byte array to convert
	 * @return converted int
	 */
	private int toInteger(byte[] b) {
		return (b[0] << 24 | (b[1] & 0xFF) << 16 | (b[2] & 0xFF) << 8 | (b[3] & 0xFF));
	}

	/**
	 * Converts the contents of the file to byte array
	 * 
	 * @param file
	 *            Filename
	 * @return file converted into byte array
	 * @throws java.io.IOException
	 */
	@SuppressWarnings("resource")
	private byte[] getBytes(File file) throws IOException {
		InputStream is = new FileInputStream(file);
		// Get the size of the file
		long length = file.length();
		// You cannot create an array using a long type.
		// It needs to be an int type.
		// Before converting to an int type, check
		// to ensure that file is not larger than Integer.MAX_VALUE.
		if (length > Integer.MAX_VALUE) {
			// File is too large
		}
		// Create the byte array to hold the data
		byte[] bytes = new byte[(int) length];
		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}
		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file " + file.getName());
		}
		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

	/**
	 * Converts an integer to bytes
	 * 
	 * @param i
	 *            integer to convert
	 * @return
	 */
	private byte[] getBytes(int i) {
		return (new byte[] { (byte) (i >> 24), (byte) (i >> 16), (byte) (i >> 8), (byte) i });
	}

	/**
	 * Matches the first four bytes of the image to the FINGERPRINT_MESSAGE
	 * 
	 * @param carrier
	 *            carrier byte array
	 * @return true if FINGERPRINT_MESSAGE found, false otherwise
	 * @throws UnsupportedEncodingException
	 */
	private boolean isStegnographed(byte[] carrier) {
		byte[] tmp = new byte[4];
		String fingerPrint = null;
		tmp = decode(carrier, 4);
		fingerPrint = new String(tmp);
		System.out.println("fingetPrint Msg " + fingerPrint);
		if (!fingerPrint.equals(FINGERPRINT_MESSAGE)) {
			return false;
		}
		return true;
	}
	private boolean isAutorized(byte[] carrier, char [] password, int len) {
		byte[] tmp = new byte[len];
		String imagePassword = null;
		tmp = decode(carrier, len);
		imagePassword = new String(tmp);
		System.out.println("Psssword from Image Msg " + imagePassword);
		if (!imagePassword.equals(new String(password))) {
			return false;
		}
		return true;
	}
}

