package service.vaxapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import service.vaxapp.model.User;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    @Query(value = "SELECT * FROM users WHERE email=:email AND user_pps=:pps", nativeQuery = true)
    User findByCredentials(String email, String pps);

    @Query(value = "SELECT * FROM users WHERE user_pps=:pps", nativeQuery = true)
    User findByPPS(String pps);

    @Query(value = "SELECT * FROM users WHERE email=:email", nativeQuery = true)
    User findByEmail(String email);

    @Query(value = "SELECT * FROM users WHERE user_pps=:input OR full_name=:input", nativeQuery = true)
    User findByPPSorName(String input);

    @Query(value = "SELECT * FROM users WHERE nationality=:nationality", nativeQuery = true)
    List<User> countByNationality(String nationality);
}
