package service.vaxapp.model;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "forum_question")
public class ForumQuestion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column
    private String title;

    @Column
    private String details;

    @Column(name = "date_submitted")
    private String dateSubmitted;

    // Bidirectional one-to-many relationship (One question may have many answers)
    @OneToMany(mappedBy = "question")
    private List<ForumAnswer> answers;

    // Bidirectional many-to-one relationship (Many questions may be asked by one
    // user)
    @ManyToOne()
    private User user;

    public ForumQuestion() {
    }

    public ForumQuestion(String title, String details, String dateSubmitted, User user) {
        this.title = title;
        this.details = details;
        this.dateSubmitted = dateSubmitted;
        this.user = user;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getDateSubmitted() {
        return dateSubmitted;
    }

    public void setDateSubmitted(String dateSubmitted) {
        this.dateSubmitted = dateSubmitted;
    }

    public List<ForumAnswer> getAnswers() {
        return answers;
    }

    public void setAnswers(List<ForumAnswer> answers) {
        this.answers = answers;
    }

    public void addAnswer(ForumAnswer answer) {
        if (this.answers == null) {
            this.answers = new ArrayList<>();
        }
        this.answers.add(answer);
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
