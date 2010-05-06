/*
KeePass for J2ME

Copyright 2007 Naomaru Itoi <nao@phoneid.org>

This file was derived from 

Java clone of KeePass - A KeePass file viewer for Java
Copyright 2006 Bill Zwicky <billzwicky@users.sourceforge.net>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

package com.keepassdroid.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.UUID;

import com.keepassdroid.stream.BetterDataInputStream;

/**
 * Tools for slicing and dicing Java and KeePass data types.
 * 
 * @author Bill Zwicky <wrzwicky@pobox.com>
 */
public class Types {
	
	public static long readLong( byte buf[], int offset ) {
		return ((long)buf[offset + 0] & 0xFF) + (((long)buf[offset + 1] & 0xFF) << 8) 
		+ (((long)buf[offset + 2] & 0xFF) << 16) + (((long)buf[offset + 3] & 0xFF) << 24) 
		+ (((long)buf[offset + 4] & 0xFF) << 32) + (((long)buf[offset + 5] & 0xFF) << 40) 
		+ (((long)buf[offset + 6] & 0xFF) << 48) + (((long)buf[offset + 7] & 0xFF) << 56);
	}
	
	public static void writeLong( long val, byte[] buf, int offset ) {
		buf[offset + 0] = (byte)(val & 0xFF);
		buf[offset + 1] = (byte)((val >>> 8) & 0xFF);
		buf[offset + 2] = (byte)((val >>> 16) & 0xFF);
		buf[offset + 3] = (byte)((val >>> 24) & 0xFF);
		buf[offset + 4] = (byte)((val >>> 32) & 0xFF);
		buf[offset + 5] = (byte)((val >>> 40) & 0xFF);
		buf[offset + 6] = (byte)((val >>> 48) & 0xFF);
		buf[offset + 7] = (byte)((val >>> 56) & 0xFF);
	}
	
  /**
   * Read a 32-bit value.
   * 
   * @param buf
   * @param offset
   * @return
   */
  public static int readInt( byte buf[], int offset ) {
    return (buf[offset + 0] & 0xFF) + ((buf[offset + 1] & 0xFF) << 8) + ((buf[offset + 2] & 0xFF) << 16)
           + ((buf[offset + 3] & 0xFF) << 24);
  }
  
  public static long readUInt( byte buf[], int offset ) {
	  return (readInt(buf, offset) & BetterDataInputStream.INT_TO_LONG_MASK);
  }

  public static int readInt(InputStream is) throws IOException {
	  byte[] buf = new byte[4];

	  is.read(buf, 0, 4);
	  
	  return Types.readInt(buf, 0);
  }
  
  public static long readUInt(InputStream is) throws IOException {
	  return (readInt(is) & BetterDataInputStream.INT_TO_LONG_MASK);
  }

  
  

  /**
   * Write a 32-bit value.
   * 
   * @param val
   * @param buf
   * @param offset
   */
  public static void writeInt( int val, byte[] buf, int offset ) {
    buf[offset + 0] = (byte)(val & 0xFF);
    buf[offset + 1] = (byte)((val >>> 8) & 0xFF);
    buf[offset + 2] = (byte)((val >>> 16) & 0xFF);
    buf[offset + 3] = (byte)((val >>> 24) & 0xFF);
  }
  
  public static byte[] writeInt(int val) {
	  byte[] buf = new byte[4];
	  writeInt(val, buf, 0);

	  return buf;
  }

  /**
   * Read an unsigned 16-bit value.
   * 
   * @param buf
   * @param offset
   * @return
   */
  public static int readShort( byte[] buf, int offset ) {
    return (buf[offset + 0] & 0xFF) + ((buf[offset + 1] & 0xFF) << 8);
  }
  
  public static int readShort(InputStream is) throws IOException {
	  byte[] buf = new byte[2];
	  
	  is.read(buf, 0, 2);
	  
	  return readShort(buf, 0); 
  }
  
  /** Write an unsigned 16-bit value
   * 
   * @param val
   * @param buf
   * @param offset
   */
  public static void writeShort(int val, byte[] buf, int offset) {
	  buf[offset + 0] = (byte)(val & 0x00FF);
	  buf[offset + 1] = (byte)((val & 0xFF00) >> 8);
  }

  public static byte[] writeShort(int val) {
	  byte[] buf = new byte[2];
	  
	  writeShort(val, buf, 0);
	  
	  return buf;
  }
                     
  /** Read an unsigned byte */
  public static int readUByte( byte[] buf, int offset ) {
    return ((int)buf[offset] & 0xFF);
  }

  /** Write an unsigned byte
   * 
   * @param val
   * @param buf
   * @param offset
   */
  public static void writeUByte(int val, byte[] buf, int offset) {
	  buf[offset] = (byte)(val & 0xFF);
  }
  
  public static byte writeUByte(int val) {
	  byte[] buf = new byte[1];
	  
	  writeUByte(val, buf, 0);
	  
	  return buf[0];
  }

  /**
   * Return len of null-terminated string (i.e. distance to null)
   * within a byte buffer.
   * 
   * @param buf
   * @param offset
   * @return
   */
  public static int strlen( byte[] buf, int offset ) {
    int len = 0;
    while( buf[offset + len] != 0 )
      len++;
    return len;
  }



  /**
   * Copy a sequence of bytes into a new array.
   * 
   * @param b - source array
   * @param offset - first byte
   * @param len - number of bytes
   * @return new byte[len]
   */
  public static byte[] extract( byte[] b, int offset, int len ) {
    byte[] b2 = new byte[len];
    System.arraycopy( b, offset, b2, 0, len );
    return b2;
  }
  
  
  private static final byte[] CRLFbuf = { 0x0D, 0x0A };
  private static final String CRLF = new String(CRLFbuf);
  private static final String SEP = System.getProperty("line.separator");
  private static final boolean REPLACE = ! SEP.equals(CRLF);
  
  public static String readCString(byte[] buf, int offset) throws UnsupportedEncodingException {
	  String jstring = new String(buf, offset, strlen(buf, offset), "UTF-8");
	  
	  if ( REPLACE ) {
		  jstring = jstring.replace(CRLF, SEP);
	  }
	  
	  return jstring;
  }

  public static int writeCString(String str, OutputStream os) throws IOException {
	  if ( str == null ) {
		  // Write out a null character
		  os.write(writeInt(1));
		  os.write(0x00);
		  return 0;
	  }
	  
	  if ( REPLACE ) {
		  str = str.replace(SEP, CRLF);
	  }
	  
	  byte[] initial = str.getBytes("UTF-8");
	  
	  int length = initial.length+1;
	  os.write(writeInt(length));
	  os.write(initial);
	  os.write(0x00);
	  
	  return length;
  }
    
  public static UUID bytestoUUID(byte[] buf) {

	  long msb = 0;
	  for (int i = 0; i < 8; i++) {
		  msb = (msb << 8) | (buf[i] & 0xff);
	  }

	  long lsb = 0;
	  for (int i = 8; i < 16; i++) {
		  lsb = (lsb << 8) | (buf[i] & 0xff);
	  }

	  return new UUID(msb, lsb);

  }

}
