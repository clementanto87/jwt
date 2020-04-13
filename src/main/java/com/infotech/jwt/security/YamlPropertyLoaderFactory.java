package com.infotech.jwt.security;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.springframework.lang.Nullable;

import java.io.IOException;
import java.util.Properties;

/**
 * to load any yml file with any name into configuration during application startup
 * It is currently used for loading role-access.yml to implement Role Based Access Control
 */
public class YamlPropertyLoaderFactory implements PropertySourceFactory {

    private static final Logger logger = LogManager.getLogger(PropertySourceFactory.class);


    @Override
    public PropertySource<?> createPropertySource(@Nullable String name, EncodedResource resource) throws IOException {
            Properties loadedProperties = this.loadYamlIntoProperties(resource.getResource());
            return new PropertiesPropertySource((StringUtils.isNotBlank(name)) ? name : resource.getResource().getFilename(), loadedProperties);
        }

    private Properties loadYamlIntoProperties(Resource resource)  {
        Properties properties = new Properties();
        try {
            YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
            factory.setResources(resource);
            factory.afterPropertiesSet();
            properties = factory.getObject();
        } catch (IllegalStateException e) {
            logger.warn("File not found!");
        }
        return properties;
    }
}
