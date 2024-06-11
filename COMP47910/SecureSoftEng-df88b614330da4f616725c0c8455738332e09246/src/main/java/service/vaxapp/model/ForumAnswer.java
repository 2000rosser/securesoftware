package service.vaxapp.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "forum_answer")
public class ForumAnswer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column
    private String body;

    @Column(name = "date_dubmitted")
    private String dateSubmitted;

    // Bidirectional many-to-one relationship (A forum question may have multiple
    // answers)
    @ManyToOne
    @JoinColumn(name = "forum_question_id", nullable = false)
    private ForumQuestion question;

    // Bidirectional many-to-one relationship (An admin may give multiple answers)
    @ManyToOne
    private User admin;

    public ForumAnswer() {
    }

    public ForumAnswer(String answer, String dateSubmitted) {
        this.body = answer;
        this.dateSubmitted = dateSubmitted;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getDateSubmitted() {
        return dateSubmitted;
    }

    public void setDateSubmitted(String dateSubmitted) {
        this.dateSubmitted = dateSubmitted;
    }

    public ForumQuestion getQuestion() {
        return question;
    }

    public void setQuestion(ForumQuestion question) {
        this.question = question;
    }

    public User getAdmin() {
        return admin;
    }

    public void setAdmin(User admin) {
        this.admin = admin;
    }
}
