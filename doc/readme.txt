urcu.h,urcu-bp.h,urcu-qsbr.h三者的区别
1.include/urcu/map/*.h下的文件仅仅为了支持在单个库时支持三种urcu实现，其本身并不影响urcu逻辑
2.include/static/(urcu.h|urcu-bp.h|urcu-qsbr.h)三个文件中实现的部分即为三者之间的差别
3.src/(urcu.h|urcu-bp.h|urcu-qsbr.h) 三个文件是对外引用的头文件
4.urcu.h中实现了
	rcu_read_lock 支持多层nest,不支持自动注册
	rcu_read_unlock 支持多层nest,支持解锁时通过futex唤醒rcu_gp
	rcu_read_ongoing 返回自身加锁标记
	synchronize_rcu 支持多个同时线程执行此函数，通过futex等待
	rcu_register_thread 每个线程会将自身注册在一个链表上，所有的rcu call将挂在各自的链上
	rcu_unregister_thread 解注册
	rcu_init, 会检查membarrier系统函数是否存在
5.urcu-bp.h中实现了
    rcu_read_lock 支持多层nest,支持自动注册reader线程
    rcu_read_unlock 支持多层nest,不支持解锁时通知
    rcu_read_ongoing 支持自动注册reader线程，返回自身加锁标记
    rcu_dereference_bp，rcu_cmpxchg_pointer_sym_bp,rcu_xchg_pointer_sym_bp,
    rcu_set_pointer_sym_bp, bp支持在_LGPL_SOURCE情况下导出这三个函数
    synchronize_rcu 与urcu实现相同，但通过poll等待，由于加锁不会通知，故需要自已通过延迟进行等待
    rcu_bp_before_fork，rcu_bp_after_fork_parent，rcu_bp_after_fork_child 自动注册的代价是需要考虑fork调用（互斥锁的问题导致）
    rcu_register_thread，rcu_unregister_thread，rcu_init 由于支持自动注册故这几个函数实现为空
    
6.urcu-qsbr.h中实现了
    通过版本号方式实现，write线程负责不断增加版本号，每个版本号之间的间隔是一个grace period,read线程显示的指明静止状态（同步write线程的版本号）
    grace period界定时，向每个线程置waiting标记，各线程在静态状态时，会检查waiting标记，如果有，会向write通知，否则不通知。
	rcu_read_lock 读锁处理为空
	rcu_read_unlock  解锁处理为空
	rcu_read_ongoing 返回rcu_reader.ctr(与其它两个相同）
	synchronize_rcu  没有采用加解锁时设置的方式来知会rcu状态，而是通过显示的通知方法，
		同步时在其它线程设置增加版本号，read线程在空闲时将标记为清除掉，并向其通过futex方式进行通知
	,rcu_register_thread,rcu_unregister_thread,
	rcu_quiescent_state,rcu_thread_offline,rcu_thread_online 由于通过标记位来实现，故需要read线程显示配合指明静止状态（同步版本号），
	线程加入，移除时需copy write的ctr计数
