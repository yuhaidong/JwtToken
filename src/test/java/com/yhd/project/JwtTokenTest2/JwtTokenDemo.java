package com.yhd.project.JwtTokenTest2;

import java.util.Map;

import com.auth0.jwt.interfaces.Claim;

/**
 * 
 * 
 * @author flx
 *
 */
public class JwtTokenDemo {

	public static void main(String[] args) throws Exception{
		
		// 生成Token
		String token = JwtToken.createToken();
		
		// 显示Token
		System.out.println("Token:" + token);
		
		System.out.println("第1次校验Token------------------------");
		
		// 解密Token
		Map<String, Claim> claims = JwtToken.verifyToken(token);
		
		System.out.println(claims.get("name").asString());
		System.out.println(claims.get("age").asString());
		System.out.println(claims.get("org") == null ? null : claims.get("org").asString());
	
		// 使用过期后的Token进行校验
		String tokenExpire = "22";
		
		System.out.println("第2次校验Token------------------------");

		Map<String, Claim> claimsExpire = JwtToken.verifyToken(tokenExpire);
		
		System.out.println("测试结束");
	}
}
