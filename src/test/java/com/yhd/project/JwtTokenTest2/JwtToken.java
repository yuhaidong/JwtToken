package com.yhd.project.JwtTokenTest2;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;



public class JwtToken {

	/**
	 * 公钥密码，保存在服务器，客户端是不会知道密码的，以防止被攻击
	 */
	public static String SECRET = "FreeMaNong";
	
	/**
	 * 生成Token
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String createToken() throws Exception{
		
		// 签发时间
		Date iatDate = new Date();
		
		// 设置过期时间 - 设置签发时间1分钟后为延迟时间
		Calendar nowTime = Calendar.getInstance();
		nowTime.add(Calendar.MINUTE, 1);
		// 得到过期时间
		Date expirensDate = nowTime.getTime();
		
		// 组合header
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("alg", "HS256");
		map.put("typ", "JWT");
		
		String token = JWT.create()
				.withHeader(map)					//header
				.withClaim("name", "Free码农")		//payload
				.withClaim("age", "28")
				.withClaim("org", "今日头条")
				.withExpiresAt(expirensDate)		//设置过期时间，过期时间要大于签发时间
				.withIssuedAt(iatDate)				//设置签发时间
				.sign(Algorithm.HMAC256(SECRET));	//加密
		
		return token;
	}
	
	/**
	 * 解密Token
	 * 
	 * @param token
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Claim> verifyToken(String token) throws Exception {
		
		JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET))
				.build();
		
		DecodedJWT jwt = null;
		
		try {
			jwt = verifier.verify(token);
			System.out.println("Token校验通过！");
		} catch (Exception e) {
			// TODO: handle exception
//			throw new RuntimeException("登录认证已过期，请重新登陆");
			e.printStackTrace();
			
			System.out.println("登录认证已过期，请重新登陆");
			System.out.println("验证Token出现错误");
		}
		
		return jwt.getClaims();
	}
}
