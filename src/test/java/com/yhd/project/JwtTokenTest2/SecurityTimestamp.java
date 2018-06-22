package com.yhd.project.JwtTokenTest2;

import java.util.Date;

public class SecurityTimestamp {

	public static String createTimestamp() {
		Date date = new Date();
		System.out.println(date);
		
		return date.toString();
	}
}
