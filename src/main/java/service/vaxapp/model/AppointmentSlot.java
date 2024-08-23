package service.vaxapp.model;

import java.time.LocalDate;
import java.time.LocalTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class AppointmentSlot {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "date")
    private LocalDate date;

    @Column(name = "start_time")
    private LocalTime startTime; // slots last 15 minutes. we can hardcode that everywhere

    // manye-to-many relationship (many appointments can take place in a centre)
    @ManyToOne(targetEntity = VaccineCentre.class)
    private VaccineCentre vaccineCentre;
    
    public AppointmentSlot() {
    }

    public AppointmentSlot(VaccineCentre vaccineCentre, LocalDate date, LocalTime startTime) {
        this.date = date;
        this.startTime = startTime;
        this.vaccineCentre = vaccineCentre;
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

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public VaccineCentre getVaccineCentre() {
        return vaccineCentre;
    }

    public void setVaccineCentre(VaccineCentre vaccineCentre) {
        this.vaccineCentre = vaccineCentre;
    }
}
