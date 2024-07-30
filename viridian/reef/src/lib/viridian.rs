pub struct Viridian {
    operational: bool
}


impl Viridian {
    pub fn new() -> Viridian{
        Viridian {
            operational: false
        }
    }

    pub fn open(&self) {}

    pub fn close(&self) {}

    pub fn is_operational(&self) -> bool {
        self.operational
    }
}

impl Drop for Viridian {
    fn drop(&mut self) -> () {
        if self.is_operational() {
            self.close()
        }
    }
}
