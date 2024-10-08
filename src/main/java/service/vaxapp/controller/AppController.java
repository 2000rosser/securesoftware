package service.vaxapp.controller;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Period;
import java.time.format.DateTimeFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import service.vaxapp.UserSession;
import service.vaxapp.model.*;
import service.vaxapp.repository.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.http.HttpServletRequest;

import java.util.concurrent.TimeUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Controller
public class AppController {
    @Autowired
    private AppointmentRepository appointmentRepository;
    @Autowired
    private ForumAnswerRepository forumAnswerRepository;
    @Autowired
    private ForumQuestionRepository forumQuestionRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private VaccineCentreRepository vaccineCentreRepository;
    @Autowired
    private VaccineRepository vaccineRepository;
    @Autowired
    private AppointmentSlotRepository appointmentSlotRepository;

    @Autowired
    private UserSession userSession;

    private static final Logger logger = LoggerFactory.getLogger(AppController.class);

    @GetMapping("/")
    public String index(Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/\" endpoint");
        ArrayList<AppointmentSlot> appSlots = (ArrayList<AppointmentSlot>) appointmentSlotRepository.findAll();
        // sort time slots by center and date
        Collections.sort(appSlots, new Comparator<AppointmentSlot>() {
            public int compare(AppointmentSlot o1, AppointmentSlot o2) {
                if (o1.getVaccineCentre().getName() == o2.getVaccineCentre().getName()) {
                    if (o1.getDate() == o2.getDate())
                        return o1.getStartTime().compareTo(o2.getStartTime());
                    return o1.getDate().compareTo(o2.getDate());
                }

                return o1.getVaccineCentre().getName().compareTo(o2.getVaccineCentre().getName());
            }
        });

        model.addAttribute("appSlots", appSlots);
        model.addAttribute("userSession", userSession);
        return "index";
    }

    @PostMapping(value = "/make-appointment")
    public String makeAppointment(@RequestParam Map<String, String> body, Model model,
            RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/make-appointment\" endpoint");
        if (!userSession.isLoggedIn()) {
            redirectAttributes.addFlashAttribute("error", "You must be logged in to make an appointment.");
            logger.info("User requested to make appointment without loggin in");
            return "redirect:/login";
        }

        // A user shouldn't have more than one pending appointment
        if (appointmentRepository.findPending(userSession.getUserId()) != null) {
            redirectAttributes.addFlashAttribute("error",
                    "You can only have one pending appointment at a time. Please check your appointment list.");
            logger.info("User tried to make more than 1 appointment");
            return "redirect:/";
        }

        Integer centerId = Integer.valueOf(body.get("center_id"));
        LocalDate date = LocalDate.parse(body.get("date"));
        LocalTime time = LocalTime.parse(body.get("time"));

        AppointmentSlot appSlot = appointmentSlotRepository.findByDetails(centerId, date, time);
        if (appSlot == null) {
            redirectAttributes.addFlashAttribute("error", "The appointment slot you selected is no longer available.");
            return "redirect:/";
        }

        Appointment app = new Appointment(appSlot.getVaccineCentre(), appSlot.getDate(), appSlot.getStartTime(),
                userSession.getUser(), "pending");
        appointmentRepository.save(app);
        appointmentSlotRepository.delete(appSlot);

        redirectAttributes.addFlashAttribute("success",
                "Your appointment has been made! Please see the details of your new appointment.");
        logger.info("Appointment created by " + userSession.getUser().getEmail());
        return "redirect:/profile";
    }

    @GetMapping("/stats")
    public String statistics(Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to /stats");
        getStats(model, "irish");
        return "stats.html";
    }

    private void getStats(Model model, String country) {
        model.addAttribute("userSession", userSession);
        model.addAttribute("totalDoses", vaccineRepository.count());
        List<User> users = vaccineRepository.findAll().stream().map(Vaccine::getUser).collect(Collectors.toList());

        model.addAttribute("dosesByNationality",
                users.stream().distinct().filter(x -> x.getNationality().equalsIgnoreCase(country)).count());
        model.addAttribute("country", country);

        long total = users.size();
        long male = users.stream().filter(x -> x.getGender().equalsIgnoreCase("male")).count();
        long female = total - male;
        Map<Integer, Double> ageRanges = new TreeMap<>();

        for (AtomicInteger i = new AtomicInteger(1); i.get() <= 8; i.incrementAndGet()) {
            long count = users.stream().filter(x -> x.getAge() / 10 == i.get()).count();
            ageRanges.put(i.get() * 10, count == 0 ? 0.0 : count / total * 100);
        }

        model.addAttribute("agerange", ageRanges);
        model.addAttribute("maleDosePercent", male * 100.0 / (double) total);
        model.addAttribute("femaleDosePercent", female * 100.0 / (double) total);
    }

    @PostMapping("/stats")
    public String statistics(Model model, @RequestParam("nationality") String country, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/make-appointment\" endpoint");
        getStats(model, country);
        return "stats.html";
    }

    /**
     * User Area
     */
    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("userSession", userSession);
        return "login";
    }

    public static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        Base64.Encoder enc = Base64.getEncoder();
        return enc.encodeToString(hash);
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static Map<String, Integer> loginAttempts = new HashMap<>();
    private static Map<String, Long> lockoutEndTime = new HashMap<>();

    @PostMapping("/login")
    public String login(@RequestParam("email") String email, @RequestParam("password") String password,
                        RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("User from:" + request.getRemoteAddr() + " is attempting to login");

        if (lockoutEndTime.containsKey(email)) {
            long endTime = lockoutEndTime.get(email);
            if (System.currentTimeMillis() < endTime) {
                redirectAttributes.addFlashAttribute("error", "Account is locked. Try again later.");
                logger.warn("User tried to login to locked account");
                return "redirect:/login";
            } else {
                lockoutEndTime.remove(email);
                loginAttempts.remove(email);
            }
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            redirectAttributes.addFlashAttribute("error", "Wrong credentials.");
            logger.error("Incorrect email used or user does not exist");
            return "redirect:/login";
        }

        try {
            byte[] salt = Base64.getDecoder().decode(user.getSalt());
            String hashedPassword = hashPassword(password, salt);

            if (!hashedPassword.equals(user.getPassword())) {
                loginAttempts.put(email, loginAttempts.getOrDefault(email, 0) + 1);
                if (loginAttempts.get(email) >= 3) {
                    lockoutEndTime.put(email, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15));
                    redirectAttributes.addFlashAttribute("error", "Too many failed attempts. Account is locked for 15 minutes.");
                    logger.warn("User " + user.getEmail() + " has been blocked from logging in for 15 minutes");
                    return "redirect:/login";
                }
                redirectAttributes.addFlashAttribute("error", "Wrong credentials.");
                logger.warn("User " + user.getEmail() + " attempted to login using incorrect credentials from IP: " + request.getRemoteAddr());
                return "redirect:/login";
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            redirectAttributes.addFlashAttribute("error", "An error occurred during login.");
            logger.error("An error occured while attempting to login.");
            return "redirect:/login";
        }

        loginAttempts.remove(email);
        lockoutEndTime.remove(email);

        if(user.getEnabled() == null || !user.getEnabled()) {
            redirectAttributes.addFlashAttribute("error", "Email address not verified. New token sent");
            logger.warn("User tried to login without verified email");
            String token = UUID.randomUUID().toString();
            user.setEmailVerificationToken(token);
            user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
            userRepository.save(user);
            sendVerificationEmail(user.getEmail(), token);
            return "redirect:/login";
        }
        
        String otp = generateOTP();
        user.setOneTimeCode(otp);
        user.setOneTimeCodeExpiry(LocalDateTime.now().plusMinutes(10));
        userRepository.save(user);
        
        sendOTPEmail(user.getEmail(), otp);
        logger.info("User " + user.getEmail() +" saved to database and one time passcode sent");

        return "redirect:/verify-otp";
    }

    // https://stackoverflow.com/a/51324081/15143894
    public static String generateOTP() {
        Random rnd = new Random();
        int number = rnd.nextInt(999999);
        return String.format("%06d", number);
    }

    private void sendOTPEmail(String email, String otp) {
        String subject = "Vaxapp (OTP)";
        String message = "Your one-time password for login is: \n" + otp;
    
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(email);
        mailMessage.setSubject(subject);
        mailMessage.setText(message);
    
        try {
            mailSender.send(mailMessage);
        } catch (Exception e) {
            logger.error("Error sending email. Please verify the SMTP server is running and the credentials are correct");
            e.printStackTrace();
        }
        logger.info("One time passcode sent to " + email);
    }

    @GetMapping("/verify-otp")
    public String showOTPVerificationPage() {
        return "verify-otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOTP(@RequestParam("otp") String otp, @RequestParam("email") String email, RedirectAttributes redirectAttributes) {

        User user = userRepository.findByEmail(email);
        if (user == null || user.getOneTimeCodeExpiry().isBefore(LocalDateTime.now())) {
            redirectAttributes.addFlashAttribute("error", "No username entered or expired OTP.");
            logger.warn("Email was not entered or OTP code expired");
            return "redirect:/login";
        }

        if (!otp.equals(user.getOneTimeCode())) {
            redirectAttributes.addFlashAttribute("error", "Invalid OTP. Please try again.");
            logger.warn("User entered incorrect OTP");
            return "redirect:/verify-otp";
        }

        user.setOneTimeCode(null);
        user.setOneTimeCodeExpiry(null);
        userRepository.save(user);

        userSession.setUserId(user.getId());

        redirectAttributes.addFlashAttribute("success", "Welcome, " + user.getFullName() + "!");
        logger.info("User " + user.getEmail() + " successfully logged in");
        return "redirect:/";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("userSession", userSession);
        return "register";
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String register( 
        @RequestParam("email") String email, @RequestParam("fullName") String name, @RequestParam("PPS") String pps, @RequestParam("password") String password, 
        @RequestParam("phoneNumber") String number, @RequestParam("address") String address, @RequestParam("dateOfBirth") String dateOfBirth, 
        @RequestParam("nationality") String nationality,  @RequestParam("gender") String gender, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Attempt from:" + request.getRemoteAddr() + " to register using email " + email);
        if (dateOfBirth.isEmpty() || email.isEmpty() || address.isEmpty()
                || name.isEmpty() || gender.isEmpty() || nationality.isEmpty()
                || number.isEmpty() || pps.isEmpty() || password.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "All fields are required!");
            return "redirect:/register";
        }
        User user = new User();
        user.setDateOfBirth(dateOfBirth);
        user.setEmail(email);
        user.setAddress(address);
        user.setFullName(name);
        user.setGender(gender);
        user.setNationality(nationality);
        user.setPhoneNumber(number);
        user.setPPS(pps);
        user.setPassword(password);
        if (userRepository.findByPPS(user.getPPS()) != null) {
            redirectAttributes.addFlashAttribute("error", "User with this PPS number or email already exists.");
            logger.warn("User from " + request.getRemoteAddr() + " tried to register to an account with PPS that already exists using email " + email);
            return "redirect:/register";
        }
        if (userRepository.findByEmail(user.getEmail()) != null) {
            redirectAttributes.addFlashAttribute("error", "User with this PPS number or email already exists.");
            logger.warn("User from " + request.getRemoteAddr() + " tried to register to an account with email that already exists using email " + email);
            return "redirect:/register";
        }
        // Ensure user is 18 or older
        if (isUserUnderage(user.getDateOfBirth())) {
            redirectAttributes.addFlashAttribute("error", "Users under 18 cannot create an account.");
            return "redirect:/register";
        }
        if (password.length() < 8) {
            redirectAttributes.addFlashAttribute("error", "Password must be at least 8 characters long.");
            return "redirect:/register";
        }

        boolean hasUpperCase = false;
        boolean hasSpecialChar = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpperCase = true;
            }
            if (!Character.isLetterOrDigit(c)) {
                hasSpecialChar = true;
            }
        }

        if (!hasUpperCase) {
            redirectAttributes.addFlashAttribute("error", "Password must contain at least one uppercase letter.");
            return "redirect:/register";
        }

        if (!hasSpecialChar) {
            redirectAttributes.addFlashAttribute("error", "Password must contain at least one special character.");
            return "redirect:/register";
        }

        try {
            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(user.getPassword(), salt);
            user.setPassword(hashedPassword);
            user.setSalt(Base64.getEncoder().encodeToString(salt).getBytes());

            String token = UUID.randomUUID().toString();
            user.setEmailVerificationToken(token);
            user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));

            user.setEnabled(false);

            userRepository.save(user);

            sendVerificationEmail(user.getEmail(), token);

            redirectAttributes.addFlashAttribute("success", "Account created! Please check your email to verify your account.");
            logger.info("Account for user " + email + " has been created");
            return "redirect:/login";
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            redirectAttributes.addFlashAttribute("error", "An error occurred during registration.");
            logger.error("Error occured during registration", e);
            return "redirect:/register";
        }
    }

    @Autowired
    private JavaMailSender mailSender;

    private void sendVerificationEmail(String email, String token) {
        String verificationUrl = "https://localhost:8082/verify?token=" + token;
        String subject = "Please Verify Your Email";
        String message = "Click the link below to verify your email address:\n" + verificationUrl;
    
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(email);
        mailMessage.setSubject(subject);
        mailMessage.setText(message);
        try {
            mailSender.send(mailMessage);
        } catch (Exception e) {
            logger.error("Error sending email. Please verify the SMTP server is running and the credentials are correct");
            e.printStackTrace();
        }
        
        logger.info("Verification email sent to " + email);
    }

    @RequestMapping(value = "/verify", method = RequestMethod.GET)
    public String verifyEmail(@RequestParam("token") String token, RedirectAttributes redirectAttributes) {
        User user = userRepository.findByEmailVerificationToken(token);

        if (user == null || user.getEmailVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            redirectAttributes.addFlashAttribute("error", "Invalid or expired verification token.");
            logger.warn("User entered an invalid token for email verification. Email: " + user.getEmail());
            return "redirect:/login";
        }

        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiry(null);
        user.setEnabled(true);

        userRepository.save(user);

        redirectAttributes.addFlashAttribute("success", "Email verified successfully! You can sign in now.");
        logger.info("User " + user.getEmail() + " successfully verified email");
        return "redirect:/login";
    }

    @GetMapping("/logout")
    public String logout() {
        userSession.setUserId(null);
        logger.info("User " + userSession.getUserId() + " logged out");
        return "redirect:/";
    }

    @GetMapping("/forum")
    public String forum(Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/forum\" endpoint");
        // Retrieve all questions and answers from database
        List<ForumQuestion> questions = forumQuestionRepository.findAll();
        model.addAttribute("questions", questions);
        model.addAttribute("userSession", userSession);
        return "forum";
    }

    @GetMapping("/ask-a-question")
    public String askAQuestion(Model model, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/ask-a-quesiton\" endpoint");
        // If not logged in or admin, return to forum
        if (!userSession.isLoggedIn() || userSession.getUser().isAdmin()) {
            redirectAttributes.addFlashAttribute("error", "Users must be logged in to ask questions.");
            return "redirect:/forum";
        }
        // If user, return ask-a-question page
        model.addAttribute("userSession", userSession);
        return "ask-a-question";
    }

    @PostMapping("/ask-a-question")
    public String askAQuestion(@RequestParam String title, @RequestParam String details, Model model,
            RedirectAttributes redirectAttributes) {
                // If user is not logged in or is admin
                if (!userSession.isLoggedIn() || userSession.getUser().isAdmin()) {
                    redirectAttributes.addFlashAttribute("error", "Users must be logged in to ask questions.");
            return "redirect:/forum";
        }

        // Create new question entry in db
        ForumQuestion newQuestion = new ForumQuestion(title, details, getDateSubmitted(), userSession.getUser());

        // Add question to database
        forumQuestionRepository.save(newQuestion);

        redirectAttributes.addFlashAttribute("success", "The question was successfully submitted.");
        logger.info("Question has been submitted");

        // Redirect to new question page
        return "redirect:/question?id=" + newQuestion.getId();
    }

    @PostMapping("/question")
    public String answerQuestion(@RequestParam String body, @RequestParam String id, Model model,
            RedirectAttributes redirectAttributes) {
        // Retrieving question
        try {
            Integer questionId = Integer.parseInt(id);
            Optional<ForumQuestion> question = forumQuestionRepository.findById(questionId);
            if (question.isPresent()) {
                // If user is admin
                if (userSession.isLoggedIn() && userSession.getUser() != null && userSession.getUser().isAdmin()) {
                    // Create new answer entry in db
                    ForumAnswer newAnswer = new ForumAnswer(body, getDateSubmitted());
                    // Save forum question and answer
                    newAnswer.setAdmin(userSession.getUser());
                    newAnswer.setQuestion(question.get());
                    forumAnswerRepository.save(newAnswer);
                    question.get().addAnswer(newAnswer);
                    forumQuestionRepository.save(question.get());

                    redirectAttributes.addFlashAttribute("success", "The answer was successfully submitted.");
                    logger.info("A question has been answered");
                    // Redirect to updated question page
                    return "redirect:/question?id=" + question.get().getId();
                } else {
                    redirectAttributes.addFlashAttribute("error",
                            "Only admins may answer questions. If you are an admin, please log in.");
                    logger.warn("Non admin user tried to ask answer a question. USERID: " + userSession.getUserId());
                    // Redirect to unchanged same question page
                    return "redirect:/question?id=" + question.get().getId();
                }
            }

        } catch (NumberFormatException e) {
            return "redirect:/forum";
        }
        return "redirect:/forum";
    }

    @GetMapping("/profile")
    public String profile(Model model, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/profile\" endpoint");
        if (!userSession.isLoggedIn()) {
            redirectAttributes.addFlashAttribute("error",
                    "You must be logged in to view your profile. If you do not already have an account, please register.");
            logger.warn("Non logged in user attempted to view profile page from IP " + request.getRemoteAddr());
            return "redirect:/login";
        }
        
        List<Appointment> apps = appointmentRepository.findByUser(userSession.getUserId());
        Collections.reverse(apps);
        
        List<Vaccine> vaxes = vaccineRepository.findByUser(userSession.getUserId());
        Collections.reverse(vaxes);
        
        model.addAttribute("vaccineCenters", vaccineCentreRepository.findAll());
        model.addAttribute("appointments", apps);
        model.addAttribute("vaccines", vaxes);
        model.addAttribute("userSession", userSession);
        model.addAttribute("userProfile", userSession.getUser());
        model.addAttribute("isSelf", true);
        model.addAttribute("userDoses", vaxes.size());
        model.addAttribute("userQuestions", forumQuestionRepository.findByUser(userSession.getUserId()).size());
        model.addAttribute("userAppts", appointmentRepository.findByUser(userSession.getUserId()).size());
        return "profile";
    }
    
    @GetMapping("/profile/{stringId}")
    public String profile(@PathVariable String stringId, Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/profile/" + stringId +"\" endpoint");
        if (stringId == null)
        return "404";
        
        //CWE-639
        if (!userSession.isLoggedIn()) {
            logger.warn("Non logged in user attempted to view \"/profile/" + stringId + "\" page from IP " + request.getRemoteAddr());
            return "redirect:/login";
        }
        
        if (!userSession.getUserId().equals(Integer.valueOf(stringId))) {
            logger.warn("user attempted to view \"/profile/" + stringId + "\", which is not theirs from IP " + request.getRemoteAddr());
            return "401";
        }
        
        try {
            Integer id = Integer.valueOf(stringId);
            Optional<User> user = userRepository.findById(id);
            
            if (!user.isPresent()) {
                return "404";
            }
            
            List<Vaccine> vaxes = vaccineRepository.findByUser(user.get().getId());

            if (userSession.isLoggedIn() && userSession.getUser().isAdmin()) {
                // admins can see everybody's appointments
                List<Appointment> apps = appointmentRepository.findByUser(user.get().getId());
                Collections.reverse(apps);
                Collections.reverse(vaxes);

                model.addAttribute("appointments", apps);
                model.addAttribute("vaccines", vaxes);
            }

            model.addAttribute("vaccineCenters", vaccineCentreRepository.findAll());
            model.addAttribute("userSession", userSession);
            model.addAttribute("userProfile", user.get());
            model.addAttribute("userQuestions", forumQuestionRepository.findByUser(user.get().getId()).size());
            model.addAttribute("userDoses", vaxes.size());
            model.addAttribute("userAppts", appointmentRepository.findByUser(user.get().getId()).size());
            return "profile";
        } catch (NumberFormatException ex) {
            return "404";
        }
    }

    @GetMapping("/cancel-appointment/{stringId}")
    public String cancelAppointment(@PathVariable String stringId, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/cancel-appointment/<stringId>\" endpoint");
        if (!userSession.isLoggedIn()){
            return "redirect:/login";
        }
        
        Integer id = Integer.valueOf(stringId);
        Appointment app = appointmentRepository.findById(id).get();
        
        if (!userSession.getUser().isAdmin() && userSession.getUser().getId() != app.getUser().getId()) {
            // Hacker detected! You can't cancel someone else's appointment!
            logger.warn("Non logged in user attempted to cancel appointment");
            return "404";
        }

        app.setStatus("cancelled");
        appointmentRepository.save(app);

        AppointmentSlot appSlot = new AppointmentSlot(app.getVaccineCentre(), app.getDate(), app.getTime());
        appointmentSlotRepository.save(appSlot);

        redirectAttributes.addFlashAttribute("success", "The appointment was successfully cancelled.");
        logger.info("Appintment has been created for user ID: " + userSession.getUserId());

        if (app.getUser().getId() != userSession.getUser().getId()) {
            return "redirect:/profile/" + app.getUser().getId();
        }

        return "redirect:/profile";
    }

    @GetMapping("/question")
    public String getQuestionById(@RequestParam(name = "id") Integer id, Model model,
            RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/question\" endpoint");
        // Retrieve question
        Optional<ForumQuestion> question = forumQuestionRepository.findById(id);
        if (question.isPresent()) {
            // Return question information
            model.addAttribute("question", question.get());
            model.addAttribute("userSession", userSession);
            return "question.html";
        } else {
            redirectAttributes.addFlashAttribute("error", "The question you requested could not be found.");
            // Redirect if question not found
            return "redirect:/forum";
        }
    }

    /**
     * Admin area
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/dashboard\" endpoint");
        if (!userSession.isLoggedIn() || !userSession.getUser().isAdmin()){
            logger.warn("Non logged in user/non-admin from IP: " + request.getRemoteAddr() + " tried to view the admin dashboard");
            return "redirect:/login";
        }
        
        model.addAttribute("users", userRepository.findAll());
        model.addAttribute("userSession", userSession);
        return "dashboard";
    }
    
    @PostMapping(value = "/find-user")
    public String findUser(@RequestParam Map<String, String> body, Model model, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/find-user\" endpoint");
        // CWE-306
        if (!userSession.isLoggedIn() || !userSession.getUser().isAdmin()){
            logger.warn("Non logged in user/non-admin from IP: " + request.getRemoteAddr() + " tried to view a user using find-user endpoint");
            return "redirect:/login";
        }
        String input = body.get("input");
        
        User user = userRepository.findByPPSorName(input);
        if (user == null) {
            logger.info("User not found");
            return "redirect:/dashboard";
        }
        
        return "redirect:/profile/" + user.getId();
    }
    
    @PostMapping(value = "/assign-vaccine")
    public String assignVaccine(@RequestParam Map<String, String> body, Model model,
    RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/assign-vaccine\" endpoint");
        if (!userSession.isLoggedIn() || !userSession.getUser().isAdmin()) {
            logger.warn("Non logged in user/non-admin from IP: " + request.getRemoteAddr() + " tried to assign a vaccine");
            return "redirect:/login";
        }
        
        LocalDate vaxDate = LocalDate.parse(body.get("date"), DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        Integer userId = Integer.valueOf(body.get("user_id"));
        Integer centreId = Integer.valueOf(body.get("center_id"));
        String vaxType = body.get("vaccine");
        
        User vaxUser = userRepository.findById(userId).get();
        VaccineCentre vaxCentre = vaccineCentreRepository.findById(centreId).get();
        redirectAttributes.addFlashAttribute("success", "The vaccine was recorded.");
        
        // See how many other doses there are per user
        List<Vaccine> vaccines = vaccineRepository.findByUser(userId);
        if (vaccines == null || vaccines.size() == 0) {
            // Getting date in 3 weeks for second vaccination between 9 and 17
            LocalDate date = vaxDate.plusDays(21);
            LocalTime time = LocalTime.of(9, 00, 00);
            Appointment appointment = appointmentRepository.findByDetails(centreId, date, time);
            while (appointment != null) {
                time = time.plusMinutes(15);
                if (time.getHour() > 17) {
                    if (date.getDayOfWeek() == DayOfWeek.FRIDAY) {
                        date = date.plusDays(3);
                    } else {
                        date = date.plusDays(1);
                    }
                    time = LocalTime.of(9, 00, 00);
                }
                appointment = appointmentRepository.findByDetails(centreId, date, time);
            }
            User user = userRepository.findById(userId).get();
            // Creating new appointment for the user
            appointment = new Appointment(vaxCentre, date, time, user, "pending");
            appointmentRepository.save(appointment);
            redirectAttributes.addFlashAttribute("success",
            "The vaccine was recorded and a new appointment at least 3 weeks from now has been made for the user.");
        }
        logger.info("vaccine recorded");
        // Save new vaccine
        Vaccine vax = new Vaccine(userSession.getUser(), vaxDate, vaxCentre, vaxUser, vaxType);
        vaccineRepository.save(vax);
        
        return "redirect:/profile/" + userId;
    }
    
    @GetMapping("/complete-appointment/{stringId}")
    public String completeAppointment(@PathVariable String stringId, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        logger.info("Connection from:" + request.getRemoteAddr() + " to \"/complete-appointment/<stringId>\" endpoint");
        if (!userSession.isLoggedIn()){
            logger.warn("Non logged in user from IP: " + request.getRemoteAddr() + " tried to assign a vaccine");
            return "redirect:/login";
        }
        
        if (!userSession.getUser().isAdmin()) {
            // Hacker detected! You can't modify if you're not an admin!
            logger.warn("Non admin from IP: " + request.getRemoteAddr() + " tried to assign a vaccine");
            return "404";
        }
        
        Integer id = Integer.valueOf(stringId);
        Appointment app = appointmentRepository.findById(id).get();

        app.setStatus("done");
        appointmentRepository.save(app);

        redirectAttributes.addFlashAttribute("success", "The appointment was marked as complete.");
        logger.info("Appointment created successfully");
        if (app.getUser().getId() != userSession.getUser().getId()) {
            return "redirect:/profile/" + app.getUser().getId();
        }

        return "redirect:/profile";
    }

    /**
     * /########################
     * <p>
     * Helpers
     * </p>
     * /#######################
     */

    private String getDateSubmitted() {
        LocalDate currentDate = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
        return currentDate.format(formatter);
    }

    private boolean isUserUnderage(String dateOfBirth) {
        LocalDate dob = LocalDate.parse(dateOfBirth, DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        return Period.between(dob, LocalDate.now()).getYears() < 18;
    }
}