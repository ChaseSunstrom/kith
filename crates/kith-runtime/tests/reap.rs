//! A create while `reap_orphans` runs as fast as it can, as kithd's controller runs it every
//! tick: the process a create makes its container in is its own to collect, and the reaper
//! must leave it. In a process of its own (this file), since a reaper takes the children of
//! every test beside it.

use kith_runtime::{Image, Runtime, Unit, reap_orphans};
use std::fs::{self, File};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

#[test]
fn a_create_is_not_robbed_of_its_process_by_the_reaper() {
    const THREADS: usize = 8;
    const EACH: usize = 6;
    let root = std::env::temp_dir().join(format!("kith-create-reap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let runtime = Arc::new(Runtime::new(root.join("runtime")).unwrap());
    let rootfs = root.join("rootfs-is-a-file");
    fs::write(&rootfs, "").unwrap();
    let image = Arc::new(Image {
        rootfs,
        entrypoint: vec!["/bin/true".into()],
        ..Image::default()
    });
    let stop = Arc::new(AtomicBool::new(false));
    let reaper = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                reap_orphans(&[]);
            }
        })
    };
    let (sender, receiver) = mpsc::channel();
    let makers: Vec<_> = (0..THREADS)
        .map(|thread| {
            let (runtime, image, sender, root) = (runtime.clone(), image.clone(), sender.clone(), root.clone());
            std::thread::spawn(move || {
                for n in 0..EACH {
                    let id = format!("reap-{}-{thread}-{n}", std::process::id());
                    let (out, err) = (
                        File::create(root.join(format!("{id}.out"))).unwrap(),
                        File::create(root.join(format!("{id}.err"))).unwrap(),
                    );
                    let said = runtime
                        .create(&id, &image, &Unit::default(), out, err)
                        .err()
                        .map(|e| e.to_string());
                    let _ = sender.send(said);
                }
            })
        })
        .collect();
    drop(sender);
    let said: Vec<_> = receiver.iter().collect();
    for maker in makers {
        maker.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    reaper.join().unwrap();
    let _ = fs::remove_dir_all(&root);
    assert_eq!(said.len(), THREADS * EACH);
    for said in said.iter().flatten() {
        assert!(
            !said.contains("No child process"),
            "the reaper took a create's process: {said}"
        );
    }
}
