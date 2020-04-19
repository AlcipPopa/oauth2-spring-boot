package com.marcusdacoregio.authservice.config.mongodb;

import com.github.mongobee.Mongobee;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.data.mongodb.core.MongoTemplate;

@Configuration
@DependsOn("mongoTemplate")
public class MongoBeeConfig {

    private static final String MONGODB_URL_FORMAT = "mongodb://stentledbclient:asauseryoucanonlyeatmysocks@localhost:27017/oauth?authSource=admin";
    private static final String MONGODB_CHANGELOGS_PACKAGE = "com.marcusdacoregio.authservice.config.mongodb.changelogs";

    @Autowired
    private MongoProperties mongoProperties;

    @Autowired
    private MongoTemplate mongoTemplate;

    @Bean
    public Mongobee mongobee() {
        Mongobee runner = new Mongobee(MONGODB_URL_FORMAT);
        runner.setMongoTemplate(mongoTemplate);
        runner.setDbName("oauth");
        runner.setChangeLogsScanPackage(MONGODB_CHANGELOGS_PACKAGE);
        return runner;
    }

}
