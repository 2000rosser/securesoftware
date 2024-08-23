package service.vaxapp.model;

import java.time.LocalDate;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.ManyToOne;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Vaccine {
    @Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

    @ManyToOne
    private User user;

    @ManyToOne
    private User admin;

    @Column(name = "date_received")
    private LocalDate dateReceived;

    @ManyToOne
    private VaccineCentre vaccineCentre;

    @Column()
    private String type;

    public Vaccine() {
    }

    public Vaccine(User admin, LocalDate dateReceived, VaccineCentre vaccineCentre, User user, String type) {
        this.admin = admin;
        this.dateReceived = dateReceived;
        this.vaccineCentre = vaccineCentre;
        this.user = user;
        this.type = type;
    }

    public Integer getId() {
        return id;
    }

    public User getAdmin() {
        return admin;
    }

    public void setAdmin(User admin) {
        this.admin = admin;
    }

    public VaccineCentre getVaccineCentre() {
        return vaccineCentre;
    }

    public void setVaccineCentre(VaccineCentre vaccineCentre) {
        this.vaccineCentre = vaccineCentre;
    }

    public LocalDate getDateReceived() {
        return dateReceived;
    }

    public void setDateReceived(LocalDate dateReceived) {
        this.dateReceived = dateReceived;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    
}
