package service.vaxapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import service.vaxapp.model.ForumAnswer;

@Repository
public interface ForumAnswerRepository extends JpaRepository<ForumAnswer, Integer> {
}
