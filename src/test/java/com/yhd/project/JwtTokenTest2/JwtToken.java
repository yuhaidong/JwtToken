package com.yhd.project.JwtTokenTest2;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtToken {

	/**
	 * 私钥密码，保存在服务器，客户端是不会知道密码的，以防止被攻击
	 */
	public static String SECRET = "飞利信内控系统";

	/**
	 * 生成Token
	 * 
	 * JWT分成3部分：1.头部（header),2.载荷（payload, 类似于飞机上承载的物品)，3.签证（signature)
	 * 
	 * 加密后这3部分密文的字符位数为：
	 *  1.头部（header)：36位，Base64编码 
	 * 	2.载荷（payload)：没准，BASE64编码
	 * 	3.签证（signature)：43位，将header和payload拼接生成一个字符串，
	 * 							使用HS256算法和我们提供的密钥（secret,服务器自己提供的一个字符串），
	 * 							对str进行加密生成最终的JWT
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String createToken() throws Exception {

		// 签发时间
		Date iatDate = new Date();

		// 设置过期时间 - 设置签发时间5秒钟后为延迟时间，这里只是做测试，实际时间会比这个长很多
		Calendar nowTime = Calendar.getInstance();
		nowTime.add(Calendar.SECOND, 5);
		// 得到过期时间
		Date expirensDate = nowTime.getTime();

		// 组合header
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("alg", "HS256");
		map.put("typ", "JWT");

		String token = JWT.create() // 首先需要通过调用jwt.create()创建一个JWTCreator实例
				.withHeader(map) // header
				.withClaim("name", "admin") // payload
				.withClaim("age", "28")
				.withClaim("org", "飞利信").withExpiresAt(expirensDate) // 设置过期时间，过期时间要大于签发时间
				.withIssuedAt(iatDate) // 设置签发时间
				.sign(Algorithm.HMAC256(SECRET)); // 使用算法器进行加密

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

		// 校验一开始，先要把保存在服务器端的密码传入校验池
		JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();

		DecodedJWT jwt = null;

		try {
			jwt = verifier.verify(token);
			System.out.println("对Token进行了校验，并且校验通过！");

		} catch (JWTDecodeException e) {
			// TODO: handle exception
			// throw new RuntimeException("登录认证已过期，请重新登陆");
			e.printStackTrace();

			System.out.println("登录认证已过期，请重新登陆");
			System.out.println("验证Token出现错误");
		}

		return jwt.getClaims();
	}

	/**
	 * 解密Token查看其是否合法
	 * 
	 * @param token
	 * @return
	 */
	public static Map<String, Claim> verifyToken2(String token) {

		Map<String, Claim> claims = null;

		try {
			// 校验一开始，先要把保存在服务器端的密码传入校验池
			JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();

			DecodedJWT jwt = null;

			jwt = verifier.verify(token);
			System.out.println("对Token进行了校验，并且校验通过！");
			
			claims = jwt.getClaims();
			
		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			System.out.println("HMAC256解码出错");

		} catch (JWTVerificationException e) {

			e.printStackTrace();
			System.out.println("验证Token出现错误，登录认证已过期，请重新登陆");

		} catch (Exception e) {

			System.out.println("未知错误");

		}

		return claims;
	}

	/**
	 * 验证一起请求（request）是否合法，包括请求时间是否超时，Token是否合法
	 * 
	 * @param dateClient
	 * @param token
	 * @param interval
	 * @return
	 */
	public static boolean verifyRequest(Date dateClient, String token, long interval) {

		boolean flag = false;
		Date dateServer = new Date();

		if (verifyToken2(token) != null) {

			// 如果请求从客户端到服务器的传输时间小于规定的时间差，则认为是正常请求
			if ((dateServer.getTime() - dateClient.getTime()) < interval) {

				System.out.println("Token验证成功，并且时间复合要求");
				flag = true;

			} else {

				System.out.println("Token验证成功，但请求超时");
				flag = false;
			}

		} else {

			System.out.println("Token验证失败");
			flag = false;
		}

		return flag;
	}

	public static String verifyRequestAndReturnToken(Date dateClient, String token, long interval) {

		String cructToken = null;
		
		if(verifyRequest(dateClient, token, interval)) {
			cructToken = token;
		}
		
		return cructToken;
		
	}

}
