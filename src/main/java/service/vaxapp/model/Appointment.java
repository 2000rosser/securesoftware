package service.vaxapp.model;

import java.time.LocalDate;
import java.time.LocalTime;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class Appointment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "date")
    private LocalDate date;

    @Column(name = "time")
    private LocalTime time;

    @Column
    private String status; // one of "pending", "cancelled", "done"

    // manye-to-one relationship (many appointments can take place in a centre)
    @ManyToOne
    private VaccineCentre vaccineCentre;

    // Bidirectional many-to-one relationship (A user may have multiple vaccine
    // appointments)
    @ManyToOne
    private User user;

    public Appointment() {
    }

    public Appointment(VaccineCentre vaccineCentre, LocalDate date, LocalTime time, User user, String status) {
        this.vaccineCentre = vaccineCentre;
        this.date = date;
        this.time = time;
        this.user = user;
        this.status = status;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
    
    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    public LocalTime getTime() {
        return time;
    }

    public void setTime(LocalTime time) {
        this.time = time;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public VaccineCentre getVaccineCentre() {
        return vaccineCentre;
    }

    public void setVaccineCentre(VaccineCentre vaccineCentre) {
        this.vaccineCentre = vaccineCentre;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
