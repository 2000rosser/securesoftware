package service.vaxapp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import service.vaxapp.controller.AppController;
import service.vaxapp.model.Appointment;
import service.vaxapp.model.AppointmentSlot;
import service.vaxapp.model.ForumQuestion;
import service.vaxapp.model.User;
import service.vaxapp.model.Vaccine;
import service.vaxapp.model.VaccineCentre;
import service.vaxapp.repository.AppointmentRepository;
import service.vaxapp.repository.AppointmentSlotRepository;
import service.vaxapp.repository.ForumQuestionRepository;
import service.vaxapp.repository.UserRepository;
import service.vaxapp.repository.VaccineCentreRepository;
import service.vaxapp.repository.VaccineRepository;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@SpringBootApplication
public class VaxApplication {
    public static void main(String[] args) {
        SpringApplication.run(VaxApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(VaccineCentreRepository vaccineCentreRepo, VaccineRepository vaccineRepo,
            AppointmentSlotRepository appointmentSlotRepo, UserRepository userRepo,
            AppointmentRepository appointmentRepo, ForumQuestionRepository forumQuestionRepo) {
        return args -> {
            System.out.println("VaxApp started");

            if (userRepo.findAll().size() == 0) {
                // init db
                byte[] salt = AppController.generateSalt();
                String saltBase64 = Base64.getEncoder().encodeToString(salt);
                String hashedPassword = AppController.hashPassword("password", salt);
                final User admin = new User("1234", hashedPassword, saltBase64.getBytes(), 
                                        "John Doe", "The Internet", "", "admin@vaxapp.com", 
                                        "07/10/1987", "Russian", "Male", true);

                final User dragos = new User("1111", hashedPassword, saltBase64.getBytes(), 
                                         "Dragos George", "Bucharest", "", "dragos@vaxapp.com", 
                                         "05/06/1999", "Romanian", "Male", false);

                final User andra = new User("2222", hashedPassword, saltBase64.getBytes(), 
                                        "Andra Antal", "Dublin", "", "andra@vaxapp.com", 
                                        "05/06/1999", "Irish", "Female", false);

                final User andrei = new User("3333", hashedPassword, saltBase64.getBytes(), 
                                         "Andrei Costin", "New York", "", "andrei@vaxapp.com", 
                                         "04/04/2000", "American", "Male", false);

                userRepo.save(admin);
                userRepo.save(dragos);
                userRepo.save(andra);
                userRepo.save(andrei);

                // Vaccine Centres
                final List<VaccineCentre> centres = new ArrayList<VaccineCentre>() {
                    {
                        add(new VaccineCentre("RDS Vaccination Centre"));
                        add(new VaccineCentre("UCD Health Centre"));
                        add(new VaccineCentre("McDonald's Drive Thru"));
                    }
                };

                for (int i = 0; i < centres.size(); ++i) {
                    vaccineCentreRepo.save(centres.get(i));
                }

                // Appointment slots
                LocalDate tomorrow = LocalDate.now().plusDays(1);
                List<AppointmentSlot> slots = new ArrayList<AppointmentSlot>();

                for (int i = 0; i < centres.size(); ++i) {
                    for (int j = 0; j < 6; ++j) {
                        for (int k = 0; k < 6; ++k) {
                            slots.add(new AppointmentSlot(centres.get(i), tomorrow.plusDays(j),
                                    LocalTime.of(9, 0).plusMinutes(k * 15)));
                        }

                    }
                }

                for (var as : slots) {
                    appointmentSlotRepo.save(as);
                }

                // Questions and answers
                ForumQuestion q1 = new ForumQuestion("Do I really need my 5th (booster) shot?",
                        "I got 2 doses of Pfizer and 2 doses of Moderna.\nDo I need another vaccine shot?",
                        LocalDate.now().toString(), andrei);
                ForumQuestion q2 = new ForumQuestion("How long do I have to wait for an appointment?",
                        "Hi! I was wondering what is the wait period between vaccination doses. Thanks!",
                        LocalDate.now().plusDays(-1).toString(), andra);

                forumQuestionRepo.save(q1);
                forumQuestionRepo.save(q2);

                // Vaccines
                Vaccine vax1 = new Vaccine(userRepo.findById(admin.getId()).get(), LocalDate.of(2021, 9, 9),
                        centres.get(0), userRepo.findById(andra.getId()).get(), "pfizer");
                Vaccine vax2 = new Vaccine(userRepo.findById(admin.getId()).get(), LocalDate.of(2022, 1, 15),
                        centres.get(0), userRepo.findById(andra.getId()).get(), "pfizer");
                Vaccine vax3 = new Vaccine(userRepo.findById(admin.getId()).get(), LocalDate.of(2020, 8, 8),
                        centres.get(1), userRepo.findById(andrei.getId()).get(), "moderna");
                Vaccine vax4 = new Vaccine(userRepo.findById(admin.getId()).get(), LocalDate.of(2022, 3, 1),
                        centres.get(1), userRepo.findById(andrei.getId()).get(), "pfizer");
                Vaccine vax5 = new Vaccine(userRepo.findById(admin.getId()).get(), LocalDate.of(2022, 2, 12),
                        centres.get(1), userRepo.findById(andrei.getId()).get(), "moderna");

                vaccineRepo.save(vax1);
                vaccineRepo.save(vax2);
                vaccineRepo.save(vax3);
                vaccineRepo.save(vax4);
                vaccineRepo.save(vax5);

                // Appointments
                List<Appointment> apps = new ArrayList<Appointment>() {
                    {
                        add(new Appointment(centres.get(0), LocalDate.of(2022, 1, 15), LocalTime.of(0, 0), andra,
                                "done"));
                        add(new Appointment(centres.get(0), LocalDate.of(2021, 9, 9), LocalTime.of(0, 0), andra,
                                "done"));
                        add(new Appointment(centres.get(0), LocalDate.of(2099, 4, 1), LocalTime.of(0, 0), dragos,
                                "pending"));
                        add(new Appointment(centres.get(1), LocalDate.of(2020, 8, 8), LocalTime.of(0, 0), andrei,
                                "done"));
                        add(new Appointment(centres.get(1), LocalDate.of(2022, 2, 12), LocalTime.of(0, 0), andrei,
                                "done"));
                        add(new Appointment(centres.get(1), LocalDate.of(2022, 2, 12), LocalTime.of(0, 0), andrei,
                                "done"));
                    }
                };
                for (var app : apps) {
                    appointmentRepo.save(app);
                }

            }
        };
    }
}
