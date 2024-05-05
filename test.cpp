#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>
#include <macoro/sync_wait.h>

#include <filesystem>
#include <iostream>
#include <ostream>
#include <thread> // NOLINT
#include <vector>
#include <cryptoTools/Common/Log.h>

using namespace osuCrypto; // NOLINT

void printParamInfo(u64 setSize, u64 numFeatures, u64 numHash, u64 numThreads, u64 cSecParam,
                    u64 StaParam) // 参数设置
{
    std::cout << "set size: " << setSize << std::endl
              << "numFeatures: " << numFeatures << std::endl
              << "numHash: " << numHash << std::endl
              << "numThreads: " << numThreads << std::endl
              << "computation security parameters: " << cSecParam << std::endl
              << "statistical security parameters: " << StaParam << std::endl
              << std::endl
              << std::endl;
}

void printInfo()
{
    std::cout << oc::Color::Green
              << "###############################################################"
                 "######\n"
              << "###############################################################"
                 "######\n"
              << "#                                                              "
                 "     #\n"
              << "#                      IP Private Union                        "
                 "     #\n"
              << "#                                                              "
                 "     #\n"
              << "###############################################################"
                 "######\n"
              << "###############################################################"
                 "######\n"
              << oc::Color::Default;
    std::cout << oc::Color::Blue << "Parameter description: \n"
              << oc::Color::Green << "-iprunion: Run the ip private Union.\n" // ip private union
              << "      -m: input set size ( 2^m ).\n"
              << "      -nf: input number of features ( nf ).\n"
              << "      -nh: input number of hashes ( nf ).\n"
              << "      -t: number of threads.\n"
              // << "      -u: Run unit test.\n"
              << "-cpsi: Run  RS21 circuit psi.\n" // cpsi
              << "      -m <value>: the log2 size of the sets.\n"
              << "      -st: ValueShareType (1 xor,0 add32).\n"
              << "      -t: number of threads.\n"
              << oc::Color::Default;
}

void iprunion(const oc::CLP &cmd)
{
    // 接收参数
    u64 setSize = 1 << cmd.getOr("m", 10); // 集合大小后面这个是默认值是2^10
    u64 numFeatures = cmd.getOr("nf", 3);  // 特征值个数默认3个
    u64 numHash = cmd.getOr("nh", 3);      // 哈希值默认值是3个
    u64 numThreads = cmd.getOr("t", 1);    // 线程个数是1个
    // 生成数据集
    // Sender试用Cuckoo，Receiver使用simple哈希
    // 共享Receiver的特征值
    // 共享Sender的特征值
    // ID做并集
    // shuffle
    // trimming
}

void cpsi(const oc::CLP &cmd)
{
    u64 setSize = 1 << cmd.getOr("m", 10); // 后面这个是默认值
    ValueShareType type =
        (cmd.get<u64>("st") == 1) ? ValueShareType::Xor : ValueShareType::add32;
    u64 numThreads = cmd.getOr("t", 1);
    printParamInfo(2, setSize, numThreads, 128, 40, 0);
    std::vector<block> recvSet(setSize);
    std::vector<block> sendSet(setSize);
    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
    u64 expeIntersection = setSize / 2;
    for (u64 i = 0; i < expeIntersection; i++)
    {
        sendSet[i].set<u64>(0, i);
        recvSet[i].set<u64>(0, i);
    }
    for (u64 i = expeIntersection; i < setSize; i++)
    {
        recvSet[i] = prng1.get<block>();
        sendSet[i] = prng1.get<block>();
    }
    auto sockets = coproto::AsioSocket::makePair();

    RsCpsiReceiver recver;
    RsCpsiSender sender;

    auto byteLength = sizeof(block);
    oc::Matrix<u8> senderValues(sendSet.size(), sizeof(block));
    std::memcpy(senderValues.data(), sendSet.data(),
                sendSet.size() * sizeof(block));
    std::memcpy(senderValues[7].data(), recvSet[8].data(), sizeof(block));
    Timer timer1;
    Timer timer2;
    Timer r;

    recver.setTimer(timer1);
    sender.setTimer(timer2);
    r.setTimePoint("");
    recver.init(setSize, setSize, byteLength, 40, prng0.get(), numThreads, type);

    sender.init(setSize, setSize, byteLength, 40, prng0.get(), numThreads, type);

    RsCpsiReceiver::Sharing rShare;
    RsCpsiSender::Sharing sShare;

    auto p0 = recver.receive(recvSet, rShare, sockets[0]);
    auto p1 = sender.send(sendSet, senderValues, sShare, sockets[1]);

    eval(p0, p1);
    r.setTimePoint("end");
    bool failed = false;
    std::vector<u64> intersection;
    for (u64 i = 0; i < recvSet.size(); ++i)
    {
        auto k = rShare.mMapping[i];

        if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k])
        {
            intersection.push_back(i);

            if (type == ValueShareType::Xor)
            {
                auto rv = *(block *)&rShare.mValues(k, 0);
                auto sv = *(block *)&sShare.mValues(k, 0);
                auto act = (rv ^ sv);
                if (recvSet[i] != act)
                {
                    if (!failed)
                        std::cout << i << " ext " << recvSet[i] << ", act " << act << " = "
                                  << rv << " " << sv << std::endl;
                    failed = true;
                }
            }
            else
            {
                for (u64 j = 0; j < 4; ++j)
                {
                    auto rv = (u32 *)&rShare.mValues(i, 0);
                    auto sv = (u32 *)&sShare.mValues(i, 0);

                    if (recvSet[i].get<u32>(j) != (sv[j] + rv[j]))
                    {
                        throw RTE_LOC;
                    }
                }
            }
        }
    }

    std::cout << sender.getTimer() << std::endl;
    std::cout << recver.getTimer() << std::endl;
    std::cout << r << std::endl;
    std::cout << "communication overhead: "
              << static_cast<double>(
                     sockets[0].bytesSent() + sockets[0].bytesReceived() +
                     sockets[1].bytesSent() + sockets[1].bytesReceived()) /
                     (1024 * 1024)
              << "MB" << std::endl;
    std::cout << "intersection  size: " << intersection.size() << std::endl;
}

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv); // 命令行输入参数
    if (cmd.isSet("cpsi"))
    {
        cpsi(cmd);
    }
    else if (cmd.isSet("iprunion"))
    {
        iprunion(cmd);
    }
    else
        printInfo();

    return 0;
}