package org.owasp.webgoat.lessons.ossspringmongodb;

import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomerRepository extends MongoRepository<Customer, String> {

  @Query("{ 'firstName' : ?#{?0} }")
  public Customer findByFirstName(String firstName);

  @Query("{ 'lastName' : ?0 }")
  public List<Customer> findByLastName(String lastName);
}
