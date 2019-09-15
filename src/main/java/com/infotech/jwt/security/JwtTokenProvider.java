package com.infotech.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This class generates and validates the token.
 */
@Component
public class JwtTokenProvider {
    private static final String AUTH_ROLES = "auth_roles";
    private static final String AUTH_GROUPS = "auth_groups";
    private static final String AUTH_ORGADMIN = "auth_orgAdmin";
    private static final String AUTH_PERMISSIONS = "auth_permissions";
    private static final String AUTHORIZATION = "Authorization";
    private static final String GROUPNAME = "groupName";
    private static final String MEMBERSYSTEMID = "memberSystemId";
    private static String secretKey = "secret-key";
    private static long validityInMilliseconds = 3600000; // 1h

    /**
     *Generates token from  email and user details of logged in user
     * @param userName
     * @param orgAdmin
     * @param
     * @return  jwt token
     */
	public String createToken(/* String userName, Integer orgAdmin, */ Map<String, List<String>> permissionMap) {
        Claims claims = Jwts.claims().setSubject("clement@gmail.com");
        //claims.put(AUTH_ORGADMIN, orgAdmin);
        claims.put(AUTH_GROUPS, permissionMap);

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.HS256, secretKey)//
                .compact();
    }

    /**
     * Resolves token present in request header.
     *
     * @param req an instance of HttpServletRequest
     * @return the token found in request
     */
    public Map<String, String> resolveToken(HttpServletRequest req) {
        HashMap<String,String> tokenDetails = new HashMap<>();
        String bearerToken = req.getHeader(AUTHORIZATION);
        String groupName = req.getHeader(GROUPNAME);
        String memeberSystemId = req.getHeader(MEMBERSYSTEMID);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            tokenDetails.put("token" ,bearerToken.substring(7, bearerToken.length()));
            tokenDetails.put(GROUPNAME , groupName);
            tokenDetails.put(MEMBERSYSTEMID, memeberSystemId);
            return tokenDetails;
        }
        return null;
    }

    /**
     * checks if logged in user is group Admin for given group
     * @param req
     * @param groupName
     * @return true/false
     */
    public boolean isTeamAdmin(HttpServletRequest req, String groupName) {
        String bearerToken = req.getHeader(AUTHORIZATION);
        String token = bearerToken.substring(7, bearerToken.length());
        Map<String, List<String>> groupList = getUserGroupList(token);
        boolean isTeamAdmin = false;
        for (Map.Entry<String, List<String>> group : groupList.entrySet()) {
            String[] values = splitTokenGroupDetails(group.getKey());
            if(values[0].contentEquals(groupName) && values[1].contentEquals("1")){
                return true;
            }

        }
        return isTeamAdmin;
    }

    /**
     * Validate token based on claims and secret key.
     *
     * @param token
     * @return true if token is parsed successfully
     * @throws JwtException
     * @throws IllegalArgumentException
     */
    public boolean validateToken(String token){
        Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        return true;
    }

    /**
     * Provide roles from token.
     *
     * @param token a string used as a token for authentication
     * @return list of roles
     */
    public List<String> getRoleList(String token){
        return (List<String>) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).
                getBody().get(AUTH_ROLES);
    }

    /**
     * Provide permissions from token
     *
     * @param token a string used as a token for authentication
     * @return list of permissions
     */
    public List<String> getPermissionsList(String token) {
		/*
		 * return (List<String>)
		 * Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).
		 * getBody().get(AUTH_PERMISSIONS);
		 */
    	  Map<String, List<String>> userGroups = getUserGroupList(token);
          List<String> permissions = new ArrayList<>();
          userGroups.forEach((key, permissionList)-> {
                  permissions.addAll(permissionList);
          });
          return permissions;
    }

    /**
     * Provides List of PermissionDto from token, current groupname and member system for which user is acting upon.
     * @param token
     * @param groupName
     * @param
     * @return list of PermissionDto names
     */
    public List<String> getPermissionsList(String token, String groupName, String memberSystemId) {
        Map<String, List<String>> userGroups = getUserGroupList(token);
        List<String> permissions = new ArrayList<>();
        userGroups.forEach((key, permissionList)-> {
                permissions.addAll(permissionList);
        });
        return permissions;
    }

    /**
     * Splits key values of hashmap stored in token into groupName, memberSystemId and teamAdmin
     * @param key
     * @return Array of Strings
     */
    public  static String[] splitTokenGroupDetails(String key){
        return key.split(":");
    }
    /**
     * Provide userName from the token
     *
     * @param token a string used as a token for authentication
     * @return the subject present in token
     */
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Provides logged in user email from token extracted from http request
     * @param req
     * @return string - email ID
     */
    public String getLoggedInUserEmail(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTHORIZATION);
        String token = bearerToken.substring(7, bearerToken.length());
        return getUsername(token);
    }

    /**
     * Provides list of groups for which logged in user has access
     * @param token
     * @return List of Groups from token
     */
    public  static Map<String, List<String>> getUserGroupList(String token) {
        return (Map<String, List<String>>) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).
                getBody().get(AUTH_GROUPS);
    }

    /**
     * This method checks if logged in user is orgAdmin or not
     * @param token
     * @return true if logged in user is orgAdmin or else false
     */
    public boolean isOrgAdmin(String token) {
        return (Boolean) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get(AUTH_ORGADMIN);
    }

    /**
     * Provide user details from token.
     *
     * @param token a string used as a token for authentication
     * @return an instance of Authentication
     */
    public Authentication getAuthentication(String token) {
    	String username = getUsername(token);
    	List<String> permissionsList = getPermissionsList(token);
        return new UsernamePasswordAuthenticationToken(username, "", permissionsList.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }

    /**
     * Provide user details from token
     * @param token
     * @param groupName
     * @param memberSystemId
     * @return an instance of Authentication
     */
    public Authentication getAuthentication(String token, String groupName, String memberSystemId ) {
        return new UsernamePasswordAuthenticationToken(getUsername(token), "", getPermissionsList(token,groupName, memberSystemId).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }
}
