package service.vaxapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import service.vaxapp.model.ForumQuestion;

import java.util.List;

@Repository
public interface ForumQuestionRepository extends JpaRepository<ForumQuestion, Integer> {
    @Query(value = "SELECT * FROM forum_question WHERE user_id=:userId", nativeQuery = true)
    List<ForumQuestion> findByUser(Integer userId);
}
