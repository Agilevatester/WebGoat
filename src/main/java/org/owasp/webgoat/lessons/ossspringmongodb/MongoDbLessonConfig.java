package org.owasp.webgoat.lessons.ossspringmongodb;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
// import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

/**
 * MongoDB configuration for the CVE-2022-22980 lesson.
 *
 * <p>Flapdoodle embedded MongoDB (on the classpath) auto-starts an in-process MongoDB and
 * auto-configures {@code MongoClient}, {@code MongoDatabaseFactory}, and {@code MongoTemplate}
 * through Spring Boot's {@code MongoAutoConfiguration}. No manual bean definitions for those are
 * needed here.
 *
 * <p>{@code @EnableMongoRepositories} is declared here — rather than in the top-level
 * {@code WebGoat.java} — so the lesson package registers its own repository without requiring any
 * changes to the application's root configuration.
 *
 * <p>The {@code seedMongoData} runner populates the embedded MongoDB with two sample customers on
 * startup so that the CVE-2022-22980 lesson has data to query against.
 */
@Configuration
// @EnableMongoRepositories(basePackageClasses = CustomerRepository.class)
public class MongoDbLessonConfig {

  /**
   * Seeds the embedded MongoDB with sample customers used by the CVE-2022-22980 lesson.
   *
   * <p>The collection is cleared before insertion so repeated restarts stay idempotent.
  
  //@Bean
  public CommandLineRunner seedMongoData(CustomerRepository repo) {
    return args -> {
      repo.deleteAll();
      repo.save(new Customer("alice", "Smith"));
      repo.save(new Customer("bob", "Jones"));
    };
  }
     */
  

}
