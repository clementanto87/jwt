package com.infotech.jwt.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * PermissionConfig file to load the role access information from
 * role-access.yml during start up and holds the file content in the bean.
 * This is shared between all microservices.All the APIs whose access are controlled
 * based on permissions(RBAC) are added role-access.yml file
 */
@Configuration
@PropertySource(factory=YamlPropertyLoaderFactory.class, value="classpath:role-access.yml", ignoreResourceNotFound = true)
@ConfigurationProperties("rbac")
public class PermissionConfig {

    private List<Details> details = new ArrayList();

    public static class Details {

        /**
         * maps permission value in yml file
         */
        private String permission;

        /**
         * Maps the key value pair specified under yml file
         */
        private Map<String, List<String>> urlmapping;

        public Map<String, List<String>> getUrlmapping() {
            return urlmapping;
        }

        public void setUrlmapping(Map<String, List<String>> urlmapping) {
            this.urlmapping = urlmapping;
        }

        public String getPermission() {
            return permission;
        }

        public void setPermission(String permission) {
            this.permission = permission;
        }

    }

    public List<Details> getDetails() {
        return details;
    }

    public void setDetails(List<Details> details) {
        this.details = details;
    }

    /**
     * provides the permission from yml file for a given request url and http method:GET,POST,PUT,DELETE
     * @param url
     * @param method
     * @return
     */
    public String getPermission(String url, String method) {
        //setting the basic permission as default value
        String mappedPermission = "ROLE_"+"NORMAL";
        for(Details detail: details){
            for(Map.Entry<String, List<String>> entry : detail.getUrlmapping().entrySet()) {
                if(url.matches(entry.getKey()) && entry.getValue().contains(method)) {
                    mappedPermission = "ROLE_" + detail.getPermission();
               	    //breaking as permission match found
		            break;
		        }
            }
        }
        return mappedPermission;
    }
}
