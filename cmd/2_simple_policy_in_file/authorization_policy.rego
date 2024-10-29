package authorization

default allow = false

allow {
    input.role == "admin"
}

allow {
    input.role == "manager"
    input.experience_years > 5
}
