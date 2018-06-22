package com.yhd.project.JwtTokenTest2;

import java.util.Date;
import java.util.Map;

import com.auth0.jwt.interfaces.Claim;

/**
 * 测试JWT的Token生成及验证
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
		
		Date dateClient = new Date(); 
		Thread.sleep(2000);
		
		System.out.println("第1次校验Token，正常通过------------------------------------------------");
		
		JwtToken.verifyRequest(dateClient, token, 3000);
		
		Map<String, Claim> claims =  JwtToken.verifyToken2(token);
		System.out.println("name=" + claims.get("name").asString());
		System.out.println("age=" + claims.get("age").asString());
		System.out.println("org=" + (claims.get("org") == null ? null : claims.get("org").asString()));
		
		// 使用过期后的Token进行校验
		System.out.println("第2次校验Token，Token错误------------------------------------------------");
		String tokenExpire = "22";
		
		JwtToken.verifyRequest(dateClient, tokenExpire, 500);

		System.out.println("第3次校验Token，Token正确，但http访问时间超时------------------------------------------------");
		
		Thread.sleep(1000);
		JwtToken.verifyRequest(dateClient, token, 500);
		
		System.out.println("第4次校验Token，Token正确，http访问也不超时，但Token已过期（10秒钟）------------------------------------------------");
		
		Thread.sleep(5000);
		JwtToken.verifyRequest(dateClient, token, 3000);
		
		System.out.println("测试结束");
	}
}
